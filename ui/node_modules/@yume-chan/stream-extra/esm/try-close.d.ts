import type { BufferedReadableStream } from "./buffered.js";
import type { ReadableStream, ReadableStreamDefaultReader } from "./stream.js";
export declare function tryClose(value: {
    close(): PromiseLike<void>;
}): Promise<boolean>;
export declare function tryClose(value: {
    close(): void;
}): boolean;
export declare function tryCancel(stream: ReadableStream<unknown>): Promise<boolean>;
export declare function tryCancel(stream: BufferedReadableStream): Promise<boolean>;
export declare function tryCancel(reader: ReadableStreamDefaultReader<unknown>): Promise<boolean>;
//# sourceMappingURL=try-close.d.ts.map