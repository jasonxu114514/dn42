class KioubitAuthButton extends HTMLElement {
    #_shadow;
    constructor() {
        super();
        this.#_shadow = this.attachShadow({ mode: 'closed' });
    }

    static #styles = '.kioubit-btn-dark,.kioubit-btn-light{font-weight:400;font-size:1rem;line-height:1.5;padding:.5em;display:flex;transition:color .15s ease-in-out,background-color .15s ease-in-out,border-color .15s ease-in-out,box-shadow .15s ease-in-out}.kioubit-btn-dark{color:#fff;background-color:#343a40;vertical-align:middle;border:1px solid transparent;border-radius:.4rem;align-items:center}.kioubit-btn-dark:hover{color:#fff;background-color:#651fff;border-color:#1d2124}.kioubit-btn-dark:focus,.kioubit-btn-light:focus{outline:0;box-shadow:0 0 0 .2rem rgba(82,88,93,.5)}.kioubit-btn-light{color:#fafafa;background-color:#2962ff;border:1px solid transparent;border-radius:.4rem;align-items:center}.kioubit-btn-light:hover{color:#fff;background-color:#311b92;border-color:#1d2124}.kioubit-btn-logo{margin-right:.5em;}';
    static #svgBase64 = btoa('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -64 1024 1024"><path d="M375.899 935.372C149.064 861.488 15.555 660.577 28.517 410.41 37.59 225.053 133.509 77.286 295.535-1.782c80.365-40.182 95.919-42.775 216.466-42.775 116.658 0 136.101 3.889 197.023 36.294C899.566 91.545 994.189 262.643 982.523 485.59c-9.073 185.357-104.992 333.124-267.018 412.192-73.884 37.59-101.104 42.775-197.023 45.367-60.922 1.296-124.435-1.296-142.582-7.777zm268.314-124.435c67.403-28.516 167.21-129.62 198.319-203.504 40.182-93.327 40.182-226.835 1.296-314.977-60.922-138.694-198.319-230.724-344.79-230.724-97.215 0-156.841 24.628-238.501 101.104-84.253 79.068-120.547 164.618-121.843 285.165-1.296 270.906 264.425 462.744 505.519 362.937zM311.089 448V156.354h89.438l7.777 256.648 107.585-128.324c102.4-123.139 108.881-128.324 158.137-128.324 28.516 0 51.848 2.592 51.848 5.185 0 3.889-58.329 72.587-128.324 152.952L469.226 460.962l98.511 110.177c54.441 60.922 110.177 123.139 124.435 139.99l24.628 28.516h-50.552c-49.256 0-55.737-6.481-154.248-121.843L408.304 494.663l-3.889 123.139-3.889 121.843h-89.438V447.999z" fill="#ffffff"/></svg>');

    connectedCallback() {
        this.#render();
    }

    static get observedAttributes() {
        return ['return', 'token'];
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (oldValue === newValue) {
            return;
        }
        switch (name) {
            case 'return':
                const returnInput = this.#_shadow.querySelector('input[name="return"]');
                returnInput && (returnInput.value = this.getReturnUrl());
                break;
            case 'token':
                const tokenInput = this.#_shadow.querySelector('input[name="token"]');
                tokenInput && (tokenInput.value = this.getTokenValue());
                break;
            default:
        }
    }

    getReturnUrl() {
        const returnAttr = this.getAttribute('return');
        if (!returnAttr) {
            return window.location.origin + window.location.pathname;
        }
        if (returnAttr.startsWith('http://') || returnAttr.startsWith('https://')) {
            return returnAttr;
        }
        if (returnAttr.startsWith('/')) {
            return window.location.origin + returnAttr
        }
        return window.location.origin + window.location.pathname + returnAttr;
    }

    getTokenValue() {
        return this.getAttribute('token') || '';
    }

    #render() {
        this.#_shadow.innerHTML = `
      <style>${this.constructor.#styles}</style>
      <form action="https://dn42.g-load.eu/auth/">
        <input type="hidden" name="return" value="${this.getReturnUrl()}">
        <input type="hidden" name="token" value="${this.getTokenValue()}">
        <button type="submit" class="kioubit-btn-dark" part="button">
          <img width="35" height="35" src="data:image/svg+xml;base64,${this.constructor.#svgBase64}" alt="Kioubit.dn42 logo" class="kioubit-btn-logo">
          Authenticate with Kioubit.dn42
        </button>
      </form>
    `;
    }
}
customElements.define('kioubit-auth-btn', KioubitAuthButton);