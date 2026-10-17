const errorMessage = new URLSearchParams(window.location.search).get("err");
const errorNotice = document.getElementById("form-error");
const noticeMessage = errorNotice.querySelector(".form-error-message");
const errorIcon = errorNotice.querySelector(".form-error-icon");
const progressIcon = errorNotice.querySelector(".form-progress-icon");

if (errorMessage) {
    errorNotice.classList.add("is-error");
    errorNotice.setAttribute("role", "alert");
    errorNotice.setAttribute("aria-live", "assertive");
    errorIcon.hidden = false;
    progressIcon.hidden = true;
    noticeMessage.textContent = errorMessage;
    errorNotice.hidden = false;
}

document.getElementById("download-form").addEventListener("submit", () => {
    errorNotice.classList.remove("is-error");
    errorNotice.classList.add("is-progress");
    errorNotice.setAttribute("role", "status");
    errorNotice.setAttribute("aria-live", "polite");
    errorIcon.hidden = true;
    progressIcon.hidden = false;
    noticeMessage.textContent = "다운로드 진행중...";
    errorNotice.hidden = false;
});
