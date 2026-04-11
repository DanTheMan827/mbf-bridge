import { isPromiseLike } from "@yume-chan/async";
export function tryClose(value) {
    try {
        const result = value.close();
        if (isPromiseLike(result)) {
            return result.then(() => true, () => false);
        }
        return true;
    }
    catch {
        return false;
    }
}
export async function tryCancel(stream) {
    try {
        await stream.cancel();
        return true;
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=try-close.js.map