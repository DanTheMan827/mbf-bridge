//! Windows taskbar jump-list support.
//!
//! Exposes `add_tasks` which appends entries to the application's "Tasks"
//! section in the Windows taskbar jump list.  Each entry re-launches the
//! current executable with a fixed set of arguments.
//!
//! This module compiles only on Windows; on all other targets the public
//! surface is a no-op stub so call sites need no `#[cfg(windows)]` guards.

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;

    use windows::core::{Interface, BSTR, GUID, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
    use windows::Win32::System::Variant::VARENUM;
    use windows::Win32::UI::Shell::{
        ICustomDestinationList, IObjectArray, IObjectCollection, IShellLinkW,
    };
    use windows::Win32::UI::Shell::PropertiesSystem::{IPropertyStore, PROPERTYKEY};

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
    fn prop_variant_bstr(s: &str) -> windows::core::Result<PROPVARIANT> {
        // `BSTR::from` allocates a COM BSTR (owned, null-terminated wide string).
        let bstr = BSTR::from(s);
        let mut pv = PROPVARIANT::default();
        // VT_BSTR = 8
        unsafe {
            pv.Anonymous.Anonymous.vt = VARENUM(8);
            // Transfer ownership of the BSTR into the PROPVARIANT.
            // The PROPVARIANT's destructor (PropVariantClear) will free it.
            pv.Anonymous.Anonymous.Anonymous.bstrVal =
                std::mem::ManuallyDrop::new(bstr.into_raw() as *mut u16);
        }
        Ok(pv)
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
            if dest_list.BeginList(&mut slots, &IObjectArray::IID).is_err() {
                return;
            }

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

/// Add entries to the Windows taskbar jump list.
///
/// `tasks` is a slice of `(display_title, argument_string)` pairs; each entry
/// re-launches the current executable with the given arguments.
///
/// On non-Windows platforms this is a no-op.
#[allow(unused_variables)]
pub fn add_tasks(tasks: &[(&str, &str)]) {
    #[cfg(windows)]
    imp::add_tasks(tasks);
}
