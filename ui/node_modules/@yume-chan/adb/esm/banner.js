export const AdbBannerKey = {
    Product: "ro.product.name",
    Model: "ro.product.model",
    Device: "ro.product.device",
    Features: "features",
};
export class AdbBanner {
    static parse(banner) {
        let state;
        let product;
        let model;
        let device;
        let features = [];
        const pieces = banner.split("::");
        if (pieces.length > 1) {
            state = (pieces[0].trim() || undefined);
            const props = pieces[1];
            for (const prop of props.split(";")) {
                // istanbul ignore if
                if (!prop) {
                    continue;
                }
                const keyValue = prop.split("=");
                if (keyValue.length !== 2) {
                    continue;
                }
                const [key, value] = keyValue;
                switch (key) {
                    case AdbBannerKey.Product:
                        product = value;
                        break;
                    case AdbBannerKey.Model:
                        model = value;
                        break;
                    case AdbBannerKey.Device:
                        device = value;
                        break;
                    case AdbBannerKey.Features:
                        features = value.split(",");
                        break;
                }
            }
        }
        return new AdbBanner(state, product, model, device, features);
    }
    #state;
    get state() {
        return this.#state;
    }
    #product;
    get product() {
        return this.#product;
    }
    #model;
    get model() {
        return this.#model;
    }
    #device;
    get device() {
        return this.#device;
    }
    #features = [];
    get features() {
        return this.#features;
    }
    // eslint-disable-next-line @typescript-eslint/max-params
    constructor(state, product, model, device, features) {
        this.#state = state;
        this.#product = product;
        this.#model = model;
        this.#device = device;
        this.#features = features;
    }
}
//# sourceMappingURL=banner.js.map