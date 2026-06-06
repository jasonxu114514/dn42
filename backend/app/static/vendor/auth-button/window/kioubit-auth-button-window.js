class KioubitAuthButtonWindow extends HTMLElement {
    #_shadow;
    #authWindow = null;
    #messageListener = null;
    #checkClosedInterval = null;
    #expiryTimeout = null;
    
    // State Data
    #currentState = 'initial';
    #authToken = null;
    #effective_mnt = null;

    #domReadyPromise = new Promise((resolve) => {
        document.addEventListener("DOMContentLoaded", resolve);
        if (document.readyState !== "loading") {
            resolve();
        }
    });

    static #styles = '.kioubit-btn-dark,.kioubit-btn-light{font-weight:400;font-size:1rem;line-height:1.5;padding:.5em;display:flex;transition:color .15s ease-in-out,background-color .15s ease-in-out,border-color .15s ease-in-out,box-shadow .15s ease-in-out}.kioubit-btn-dark{color:#fff;background-color:#343a40;vertical-align:middle;border:1px solid transparent;border-radius:.4rem;align-items:center}.kioubit-btn-dark:hover{color:#fff;background-color:#651fff;border-color:#1d2124}.kioubit-btn-dark:focus,.kioubit-btn-light:focus{outline:0;box-shadow:0 0 0 .2rem rgba(82,88,93,.5)}.kioubit-btn-light{color:#fafafa;background-color:#2962ff;border:1px solid transparent;border-radius:.4rem;align-items:center}.kioubit-btn-light:hover{color:#fff;background-color:#311b92;border-color:#1d2124}.kioubit-btn-logo{margin-right:.5em;}';    

    static #svgLogo = btoa('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -64 1024 1024"><path d="M375.899 935.372C149.064 861.488 15.555 660.577 28.517 410.41 37.59 225.053 133.509 77.286 295.535-1.782c80.365-40.182 95.919-42.775 216.466-42.775 116.658 0 136.101 3.889 197.023 36.294C899.566 91.545 994.189 262.643 982.523 485.59c-9.073 185.357-104.992 333.124-267.018 412.192-73.884 37.59-101.104 42.775-197.023 45.367-60.922 1.296-124.435-1.296-142.582-7.777zm268.314-124.435c67.403-28.516 167.21-129.62 198.319-203.504 40.182-93.327 40.182-226.835 1.296-314.977-60.922-138.694-198.319-230.724-344.79-230.724-97.215 0-156.841 24.628-238.501 101.104-84.253 79.068-120.547 164.618-121.843 285.165-1.296 270.906 264.425 462.744 505.519 362.937zM311.089 448V156.354h89.438l7.777 256.648 107.585-128.324c102.4-123.139 108.881-128.324 158.137-128.324 28.516 0 51.848 2.592 51.848 5.185 0 3.889-58.329 72.587-128.324 152.952L469.226 460.962l98.511 110.177c54.441 60.922 110.177 123.139 124.435 139.99l24.628 28.516h-50.552c-49.256 0-55.737-6.481-154.248-121.843L408.304 494.663l-3.889 123.139-3.889 121.843h-89.438V447.999z" fill="#ffffff"/></svg>');
    static #svgCheck = btoa('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>');

    constructor() {
        super();
        this.#_shadow = this.attachShadow({ mode: 'closed' });
    }

    async connectedCallback() {
        this.#render();
        this.#setupEventListeners();

        await this.#domReadyPromise;
        const prefix = this.getAttribute("localStoragePrefix");
        const validityAttr = this.getAttribute("validity");

        if (prefix) {
            const rawData = window.localStorage.getItem(`${prefix}-kauth-data`);
            if (rawData) {
                try {
                    const data = JSON.parse(rawData);
                    const now = Math.floor(Date.now() / 1000);
                    const validitySeconds = (parseInt(validityAttr) || Infinity) * 60;
                    const elapsed = now - data.time;

                    if (elapsed < validitySeconds) {
                        this.#authToken = data.token;
                        this.#effective_mnt = data.mnt;
                        this.#setUIState('success');

                        this.dispatchEvent(new CustomEvent('authsuccess', { detail: { token: this.#authToken } }));

                        // Schedule auto-reset for the remaining time
                        if (validitySeconds !== Infinity) {
                            this.#expiryTimeout = setTimeout(() => this.reset(), (validitySeconds - elapsed) * 1000);
                        }
                    } else {
                        window.localStorage.removeItem(`${prefix}-kauth-data`);
                    }
                } catch (e) { console.error("Auth storage corrupted", e); }
            }
        }
    }

    disconnectedCallback() {
        clearTimeout(this.#expiryTimeout);
        this.#cleanup(false);
    }

    static get observedAttributes() {
        return [];
    }

    // Public API
    getAuthToken() { return this.#authToken; }
    getEffectiveMnt() { return this.#effective_mnt; }
    
    /**
     * Resets the component to its initial logged-out state.
     */
    reset() {
        clearTimeout(this.#expiryTimeout);
        const localStoragePrefix = this.getAttribute("localStoragePrefix");
        if (localStoragePrefix) {
            window.localStorage.removeItem(`${localStoragePrefix}-kauth-data`);
        }
        this.#authToken = null;
        this.#effective_mnt = null;
        this.#cleanup(false);
        this.#setUIState('initial');
        this.dispatchEvent(new CustomEvent('authreset'));
    }

    /**
     * UI State Manager
     * @param {'initial'|'loading'|'success'} state 
     */
    #setUIState(state) {
        this.#currentState = state;
        const button = this.#_shadow.querySelector('button');
        const img = this.#_shadow.querySelector('img');
        if (!button || !img) return;

        const textNode = button.childNodes[2]; 

        switch (state) {
            case 'initial':
                button.disabled = false;
                button.style.removeProperty('background-color'); // Revert to class CSS
                button.classList.remove('success-state');
                img.style.opacity = '1';
                img.src = `data:image/svg+xml;base64,${KioubitAuthButtonWindow.#svgLogo}`;
                if (textNode) textNode.textContent = 'Authenticate with Kioubit.dn42';
                
                this.dispatchEvent(new CustomEvent('loadingchange', { detail: { isLoading: false } }));
                break;

            case 'loading':
                button.disabled = true;
                img.style.opacity = '0.5';
                if (textNode) textNode.textContent = 'Authenticating... (Check opened window)';
                
                this.dispatchEvent(new CustomEvent('loadingchange', { detail: { isLoading: true } }));
                break;

            case 'success':
                button.disabled = false;
                button.style.backgroundColor = '#28a745';
                img.style.opacity = '1';
                img.src = `data:image/svg+xml;base64,${KioubitAuthButtonWindow.#svgCheck}`;
                if (textNode) textNode.textContent = `Logged in as ${this.#effective_mnt || 'Unknown'}`;
                
                this.dispatchEvent(new CustomEvent('loadingchange', { detail: { isLoading: false } }));
                break;
        }
    }

    #handleAuth(event) {
        event.preventDefault();

        if (this.#currentState === 'loading') {
            this.#authWindow?.focus();
            return;
        }
        
        if (this.#currentState === 'success') {
            this.reset();
            return;
        }

        this.#setUIState('loading');

        const authUrl = new URL('https://dn42.g-load.eu/auth/');
        authUrl.searchParams.set('return', this.#getReturnUrl());
        authUrl.searchParams.set('token', this.#getTokenValue());

        this.#authWindow = window.open(
            authUrl.toString(),
            'kioubitAuth',
            'width=500,height=700,scrollbars=yes,resizable=yes'
        );

        this.#messageListener = (e) => {
            if (e.origin !== location.origin) return;

            if (e.data.type === 'AUTH_SUCCESS') {
                this.#processSuccess(e.data.token);
            } else if (e.data.type === 'AUTH_ERROR') {
                this.dispatchEvent(new CustomEvent('autherror', {
                    detail: { error: e.data.error }
                }));
                this.#cleanup(false);
            }
        };

        window.addEventListener('message', this.#messageListener);

        this.#checkClosedInterval = setInterval(() => {
            if (this.#authWindow?.closed !== false) {
                this.#cleanup(false);
            }
        }, 1000);
    }

    #processSuccess(token) {
        this.#authToken = token;
        const validityAttr = this.getAttribute("validity");

        try {
            const urlParams = new URLSearchParams("?" + this.#authToken);
            const paramJSON = JSON.parse(atob(urlParams.get("params")));
            this.#effective_mnt = paramJSON["effective_mnt"];
        } catch (e) { this.#effective_mnt = "User"; }

        const localStoragePrefix = this.getAttribute("localStoragePrefix");
        if (localStoragePrefix) {
            window.localStorage.setItem(`${localStoragePrefix}-kauth-data`, JSON.stringify({
                "mnt": this.#effective_mnt,
                "token": token,
                "time":  Math.floor(Date.now() / 1000)
            }));
        }

        // Schedule auto-reset
        if (validityAttr) {
            clearTimeout(this.#expiryTimeout);
            this.#expiryTimeout = setTimeout(() => this.reset(), parseInt(validityAttr) * 60 * 1000);
        }

        this.#setUIState('success');
        this.dispatchEvent(new CustomEvent('authsuccess', { detail: { token: this.#authToken } }));
        this.#cleanup(true);
    }

    #cleanup(keepSuccessState = false) {
        if (this.#checkClosedInterval) {
            clearInterval(this.#checkClosedInterval);
            this.#checkClosedInterval = null;
        }

        if (this.#messageListener) {
            window.removeEventListener('message', this.#messageListener);
            this.#messageListener = null;
        }

        if (this.#authWindow && !this.#authWindow.closed) {
            this.#authWindow.close();
        }
        this.#authWindow = null;

        if (!keepSuccessState && this.#currentState !== 'success') {
            this.#setUIState('initial');
        }
    }

    #getReturnUrl() {
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

    #getTokenValue() {
        return this.getAttribute('token') || '';
    }

    #setupEventListeners() {
        const button = this.#_shadow.querySelector('button');
        button?.addEventListener('click', this.#handleAuth.bind(this));
    }

    #render() {
        this.#_shadow.innerHTML = `
      <style>${KioubitAuthButtonWindow.#styles}</style>
        <button type="submit" class="kioubit-btn-dark" part="button">
          <img width="35" height="35" src="data:image/svg+xml;base64,${KioubitAuthButtonWindow.#svgLogo}" alt="Kioubit.dn42 logo" class="kioubit-btn-logo">
          Authenticate with Kioubit.dn42
        </button>
    `;
    }
}
customElements.define('kioubit-auth-btn-window', KioubitAuthButtonWindow);
