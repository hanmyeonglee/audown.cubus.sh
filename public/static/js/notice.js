const notice = document.getElementById("form-error");
const message = notice.querySelector(".form-error-message");
const errorIcon = notice.querySelector(".form-error-icon");

export function showNotice(text) {
    notice.classList.add("is-error");
    notice.setAttribute("role", "alert");
    notice.setAttribute("aria-live", "assertive");
    errorIcon.hidden = false;
    message.textContent = text;
    notice.hidden = false;
}

export function hideNotice() {
    notice.classList.remove("is-error");
    notice.hidden = true;
    message.textContent = "";
}
