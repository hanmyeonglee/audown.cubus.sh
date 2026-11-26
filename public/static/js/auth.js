const INAPP_BROWSER_RE = /KAKAOTALK|NAVER|Instagram|Line|FBAN|FBAV/i;

function isInAppOrUnsupportedBrowser() {
    const ua = navigator.userAgent || "";
    const inApp = INAPP_BROWSER_RE.test(ua);
    const noWebAuthn = typeof window.PublicKeyCredential === "undefined" || !navigator.credentials;
    return { inApp, noWebAuthn, unsupported: inApp || noWebAuthn };
}

function base64URLToUint8Array(value) {
    const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const binary = window.atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function arrayBufferToBase64URL(buffer) {
    if (!buffer) {
        return "";
    }
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function showError(message) {
    const el = document.getElementById("auth-error");
    const msg = document.getElementById("auth-error-message");
    if (!el || !msg) {
        return;
    }
    el.classList.add("is-error");
    msg.textContent = message;
    el.hidden = false;
}

function hideError() {
    const el = document.getElementById("auth-error");
    const msg = document.getElementById("auth-error-message");
    if (!el || !msg) {
        return;
    }
    el.classList.remove("is-error");
    msg.textContent = "";
    el.hidden = true;
}

function setButtonBusy(button, labelEl, arrowEl, spinnerEl, busy, idleText, busyText) {
    button.disabled = busy;
    button.setAttribute("aria-busy", String(busy));
    labelEl.textContent = busy ? busyText : idleText;
    if (arrowEl) {
        arrowEl.hidden = busy;
    }
    if (spinnerEl) {
        spinnerEl.hidden = !busy;
    }
}

function mapWebAuthnError(error, isRegister) {
    if (error && typeof error.serverMessage === "string" && error.serverMessage) {
        return error.serverMessage;
    }
    if (!error) {
        return isRegister ? "패스키 등록에 실패했습니다." : "로그인에 실패했습니다.";
    }
    switch (error.name) {
        case "NotAllowedError":
            return "인증이 취소되었거나 시간이 초과되었습니다. 다시 시도해주세요.";
        case "InvalidStateError":
            return "이 기기에는 이미 패스키가 등록되어 있습니다.";
        case "NotSupportedError":
            return "이 브라우저에서는 패스키를 지원하지 않습니다. Safari 또는 Chrome에서 열어주세요.";
        case "SecurityError":
            return "보안 연결(HTTPS) 또는 기본 브라우저에서 다시 시도해주세요.";
        case "TypeError":
            return "네트워크 오류가 발생했습니다. 인터넷 연결을 확인해주세요.";
        default:
            return isRegister
                ? "패스키 등록 중 오류가 발생했습니다. 다시 시도해주세요."
                : "로그인 중 오류가 발생했습니다. 다시 시도해주세요.";
    }
}

async function copyCurrentURL(copyLabel) {
    const url = window.location.href;
    let copied = false;
    try {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
            await navigator.clipboard.writeText(url);
            copied = true;
        }
    } catch {
        copied = false;
    }

    if (!copied) {
        const input = document.createElement("textarea");
        input.value = url;
        input.setAttribute("readonly", "");
        input.className = "sr-copy-buffer";
        document.body.appendChild(input);
        input.select();
        try {
            copied = document.execCommand("copy");
        } catch {
            copied = false;
        }
        document.body.removeChild(input);
    }

    if (copyLabel) {
        copyLabel.textContent = copied ? "링크가 복사되었습니다 ✓" : "주소창의 링크를 직접 복사해주세요";
        window.setTimeout(() => {
            copyLabel.textContent = "링크 복사";
        }, 2500);
    }
}

function setupInAppBanner() {
    const status = isInAppOrUnsupportedBrowser();
    const banner = document.getElementById("inapp-banner");
    const copyBtn = document.getElementById("copy-link-button");
    const copyLabel = document.getElementById("copy-link-label");

    if (banner && status.unsupported) {
        banner.hidden = false;
    }
    if (copyBtn) {
        copyBtn.addEventListener("click", () => {
            void copyCurrentURL(copyLabel);
        });
    }
    return status;
}

async function postJSON(path, payload) {
    const response = await fetch(path, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    let data = null;
    try {
        data = await response.json();
    } catch {
        data = null;
    }
    if (!response.ok) {
        const err = new Error((data && data.error) || `HTTP ${response.status}`);
        err.serverMessage = data && data.error ? data.error : "";
        err.status = response.status;
        throw err;
    }
    return data;
}

function extractInviteTokenFromPath() {
    const prefix = "/invite/";
    if (!window.location.pathname.startsWith(prefix)) {
        return "";
    }
    const rest = window.location.pathname.slice(prefix.length);
    if (!rest || rest.includes("/")) {
        return "";
    }
    try {
        return decodeURIComponent(rest);
    } catch {
        return rest;
    }
}

function prepareCreationOptions(publicKey) {
    const opts = {
        ...publicKey,
        challenge: base64URLToUint8Array(publicKey.challenge),
        user: {
            ...publicKey.user,
            id: base64URLToUint8Array(publicKey.user.id),
        },
    };
    if (Array.isArray(publicKey.excludeCredentials)) {
        opts.excludeCredentials = publicKey.excludeCredentials.map((item) => ({
            ...item,
            id: base64URLToUint8Array(item.id),
        }));
    }
    return opts;
}

function serializeRegistrationCredential(cred) {
    const response = cred.response;
    const payload = {
        id: cred.id,
        rawId: arrayBufferToBase64URL(cred.rawId),
        type: cred.type,
        clientExtensionResults: typeof cred.getClientExtensionResults === "function"
            ? cred.getClientExtensionResults()
            : {},
        response: {
            attestationObject: arrayBufferToBase64URL(response.attestationObject),
            clientDataJSON: arrayBufferToBase64URL(response.clientDataJSON),
        },
    };
    if (cred.authenticatorAttachment) {
        payload.authenticatorAttachment = cred.authenticatorAttachment;
    }
    if (typeof response.getTransports === "function") {
        const transports = response.getTransports();
        if (Array.isArray(transports) && transports.length > 0) {
            payload.response.transports = transports;
        }
    }
    return payload;
}

function prepareRequestOptions(publicKey) {
    const opts = {
        ...publicKey,
        challenge: base64URLToUint8Array(publicKey.challenge),
    };
    if (Array.isArray(publicKey.allowCredentials)) {
        opts.allowCredentials = publicKey.allowCredentials.map((item) => ({
            ...item,
            id: base64URLToUint8Array(item.id),
        }));
    }
    return opts;
}

function serializeAssertionCredential(cred) {
    const response = cred.response;
    const payload = {
        id: cred.id,
        rawId: arrayBufferToBase64URL(cred.rawId),
        type: cred.type,
        clientExtensionResults: typeof cred.getClientExtensionResults === "function"
            ? cred.getClientExtensionResults()
            : {},
        response: {
            authenticatorData: arrayBufferToBase64URL(response.authenticatorData),
            clientDataJSON: arrayBufferToBase64URL(response.clientDataJSON),
            signature: arrayBufferToBase64URL(response.signature),
        },
    };
    if (cred.authenticatorAttachment) {
        payload.authenticatorAttachment = cred.authenticatorAttachment;
    }
    if (response.userHandle) {
        payload.response.userHandle = arrayBufferToBase64URL(response.userHandle);
    }
    return payload;
}

function initInvitePage(browserStatus) {
    const button = document.getElementById("register-button");
    const labelEl = document.getElementById("register-button-label");
    const arrowEl = document.getElementById("register-button-arrow");
    const spinnerEl = document.getElementById("register-button-spinner");
    if (!button || !labelEl) {
        return;
    }

    const idleText = labelEl.textContent || "이 기기로 시작하기 (패스키 등록)";
    if (browserStatus.noWebAuthn) {
        button.disabled = true;
        return;
    }

    let inFlight = false;
    button.addEventListener("click", async () => {
        if (inFlight) {
            return;
        }
        hideError();
        const token = extractInviteTokenFromPath();
        if (!token) {
            showError("초대 링크가 올바르지 않습니다.");
            return;
        }

        inFlight = true;
        setButtonBusy(button, labelEl, arrowEl, spinnerEl, true, idleText, "패스키 등록 중...");
        try {
            const beginData = await postJSON("/auth/passkey/register/begin", { token });
            const publicKey = prepareCreationOptions(beginData.publicKey);
            const credential = await navigator.credentials.create({ publicKey });
            if (!credential) {
                throw new DOMException("No credential returned", "NotAllowedError");
            }
            const serialized = serializeRegistrationCredential(credential);
            await postJSON("/auth/passkey/register/finish", {
                challenge_id: beginData.challenge_id,
                token,
                credential: serialized,
            });
            window.location.replace("/");
        } catch (error) {
            showError(mapWebAuthnError(error, true));
            setButtonBusy(button, labelEl, arrowEl, spinnerEl, false, idleText, "패스키 등록 중...");
            inFlight = false;
        }
    });
}

function initLoginPage(browserStatus) {
    const button = document.getElementById("login-button");
    const labelEl = document.getElementById("login-button-label");
    const arrowEl = document.getElementById("login-button-arrow");
    const spinnerEl = document.getElementById("login-button-spinner");
    if (!button || !labelEl) {
        return;
    }

    const idleText = labelEl.textContent || "지문 / 얼굴 인식으로 로그인";
    if (browserStatus.noWebAuthn) {
        button.disabled = true;
        return;
    }

    let inFlight = false;
    button.addEventListener("click", async () => {
        if (inFlight) {
            return;
        }
        hideError();
        inFlight = true;
        setButtonBusy(button, labelEl, arrowEl, spinnerEl, true, idleText, "인증 확인 중...");
        try {
            const beginData = await postJSON("/auth/passkey/login/begin", {});
            const publicKey = prepareRequestOptions(beginData.publicKey);
            const credential = await navigator.credentials.get({ publicKey });
            if (!credential) {
                throw new DOMException("No assertion returned", "NotAllowedError");
            }
            const serialized = serializeAssertionCredential(credential);
            await postJSON("/auth/passkey/login/finish", {
                challenge_id: beginData.challenge_id,
                credential: serialized,
            });
            window.location.replace("/");
        } catch (error) {
            showError(mapWebAuthnError(error, false));
            setButtonBusy(button, labelEl, arrowEl, spinnerEl, false, idleText, "인증 확인 중...");
            inFlight = false;
        }
    });
}

const browserStatus = setupInAppBanner();
const pageKind = document.body.dataset.authPage;
if (pageKind === "invite") {
    initInvitePage(browserStatus);
} else if (pageKind === "login") {
    initLoginPage(browserStatus);
}
