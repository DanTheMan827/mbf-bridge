use std::fs;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[cfg(windows)]
struct TaskEntry {
    title: String,
    args: String,
}

#[cfg(windows)]
fn tasks_file_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    let mut path = PathBuf::from(base);
    path.push("DanTheMan827");
    path.push("mbf-bridge");
    fs::create_dir_all(&path).ok()?;
    path.push("jump_tasks.json");
    Some(path)
}

#[cfg(windows)]
fn load_tasks() -> Vec<TaskEntry> {
    if let Some(path) = tasks_file_path() {
        if let Ok(data) = fs::read_to_string(path) {
            if let Ok(list) = serde_json::from_str::<Vec<TaskEntry>>(&data) {
                return list;
            }
        }
    }
    Vec::new()
}

#[cfg(windows)]
fn save_tasks(tasks: &[TaskEntry]) {
    if let Some(path) = tasks_file_path() {
        let _ = fs::write(path, serde_json::to_string_pretty(tasks).unwrap_or_default());
    }
}

/// Prepend a task (move to front if exists), persist, and update jump list
#[cfg(windows)]
pub fn prepend_task(title: &str, args: &str) {
    let mut tasks = load_tasks();
    // Remove any existing matching task
    tasks.retain(|t| !(t.title == title && t.args == args));
    // Insert at front
    tasks.insert(0, TaskEntry { title: title.to_string(), args: args.to_string() });
    save_tasks(&tasks);
    // Call jump list update
    let task_refs: Vec<(&str, &str)> = tasks.iter().map(|t| (t.title.as_str(), t.args.as_str())).collect();
    imp::add_tasks(&task_refs);
}

/// Write all tasks to the jump list
#[cfg(windows)]
pub fn write_tasks() {
    let tasks = load_tasks();
    // Call jump list update
    let task_refs: Vec<(&str, &str)> = tasks.iter().map(|t| (t.title.as_str(), t.args.as_str())).collect();
    imp::add_tasks(&task_refs);
}

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;

    use windows::core::{Interface, BSTR, GUID, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
    use windows::Win32::UI::Shell::{
        ICustomDestinationList, IShellLinkW,
        Common::{IObjectArray, IObjectCollection},
    };
    use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
    use windows::Win32::Foundation::PROPERTYKEY;

    // CLSIDs from the Windows SDK.
    // CLSID_DestinationList            = {77f10cf0-3db5-4966-b520-b7c54fd35ed6}
    const CLSID_DESTINATION_LIST: GUID =
        GUID::from_u128(0x77f10cf0_3db5_4966_b520_b7c54fd35ed6);
    // CLSID_EnumerableObjectCollection = {2d3468c1-36a7-43b6-ac24-d3f02fd9607a}
    const CLSID_ENUM_OBJ_COLLECTION: GUID =
        GUID::from_u128(0x2d3468c1_36a7_43b6_ac24_d3f02fd9607a);
    // CLSID_ShellLink                  = {00021401-0000-0000-c000-000000000046}
    const CLSID_SHELL_LINK: GUID =
        GUID::from_u128(0x00021401_0000_0000_c000_000000000046);

    // PKEY_Title = {F29F85E0-4FF9-1068-AB91-08002B27B3D9}, pid=2
    const PKEY_TITLE: PROPERTYKEY = PROPERTYKEY {
        fmtid: GUID::from_u128(0xF29F85E0_4FF9_1068_AB91_08002B27B3D9),
        pid: 2,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0u16))
            .collect()
    }

    /// Build a `PROPVARIANT` holding a `VT_BSTR` value.
    ///
    /// The `BSTR` is an owned, reference-counted string allocated by the COM
    /// runtime, so `IPropertyStore::SetValue` always receives a valid pointer
    /// regardless of when it makes its internal copy.
    #[allow(unsafe_op_in_unsafe_fn)]
    fn prop_variant_bstr(s: &str) -> windows::core::Result<PROPVARIANT> {
        let bstr = BSTR::from(s);
        Ok(PROPVARIANT::from(bstr))
    }

    pub fn add_tasks(tasks: &[(&str, &str)]) {
        unsafe {
            // Initialise COM (apartment-threaded); ignore if already initialised.
            let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

            let dest_list: ICustomDestinationList =
                match CoCreateInstance(&CLSID_DESTINATION_LIST, None, CLSCTX_INPROC_SERVER) {
                    Ok(v) => v,
                    Err(_) => return,
                };

            let mut slots: u32 = 0;
            let _: Option<IObjectArray> = match dest_list.BeginList(&mut slots).ok() {
                Some(arr) => Some(arr),
                None => return,
            };

            let collection: IObjectCollection = match CoCreateInstance(
                &CLSID_ENUM_OBJ_COLLECTION,
                None,
                CLSCTX_INPROC_SERVER,
            ) {
                Ok(v) => v,
                Err(_) => {
                    let _ = dest_list.AbortList();
                    return;
                }
            };

            let exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(_) => {
                    let _ = dest_list.AbortList();
                    return;
                }
            };
            let exe_wide: Vec<u16> = exe
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0u16))
                .collect();

            for (title, args) in tasks {
                let link: IShellLinkW =
                    match CoCreateInstance(&CLSID_SHELL_LINK, None, CLSCTX_INPROC_SERVER) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                let _ = link.SetPath(PCWSTR(exe_wide.as_ptr()));
                let args_wide = to_wide(args);
                let _ = link.SetArguments(PCWSTR(args_wide.as_ptr()));
                let desc_wide = to_wide(title);
                let _ = link.SetDescription(PCWSTR(desc_wide.as_ptr()));

                // Set the visible jump-list title via IPropertyStore (VT_BSTR).
                if let Ok(store) = link.cast::<IPropertyStore>() {
                    if let Ok(pv) = prop_variant_bstr(title) {
                        let _ = store.SetValue(&PKEY_TITLE, &pv);
                        let _ = store.Commit();
                        // pv drops here; its destructor calls PropVariantClear which
                        // frees the BSTR allocated in prop_variant_bstr.
                    }
                }

                let link_unknown: windows::core::IUnknown = link.cast().unwrap();
                let _ = collection.AddObject(&link_unknown);
            }

            if let Ok(arr) = collection.cast::<IObjectArray>() {
                let _ = dest_list.AddUserTasks(&arr);
            }
            let _ = dest_list.CommitList();
        }
    }
}
