import { hideNotice, showNotice } from "./notice.js";
import { extractVideoId, fetchVideoDetails } from "./youtube-api.js";
import { resetVideoPreview, showVideoPreview } from "./video-preview.js";
import {
    resetTimeRange,
    setTimeRangeDisabled,
    setVideoDuration,
    syncTimeRangeFormValues,
} from "./time-range.js";

const form = document.getElementById("download-form");
const urlInput = document.getElementById("url");
const urlSubmission = document.getElementById("url-submission");
const downloadTokenInput = document.getElementById("download-token");
const lookupButton = document.getElementById("lookup-button");
const formField = urlInput.closest(".form-field");
const urlInputWrap = urlInput.closest(".url-input-wrap");
const urlSpinner = urlInputWrap.querySelector(".url-loading-spinner");
const submitButton = document.getElementById("submit-button");
const submitLabel = document.getElementById("submit-label");
const submitArrow = submitButton.querySelector(".button-arrow");
const submitSpinner = submitButton.querySelector(".button-loading-spinner");
const resultElements = [
    document.getElementById("video-preview"),
    document.getElementById("time-fieldset"),
    submitButton,
];

let loadedVideoId = "";
let requestSequence = 0;
let activeRequest = null;
let resultsHideTimer = 0;
let lookupHideTimer = 0;
let downloadResponsePollTimer = 0;
let downloadCompleteResetTimer = 0;

const downloadResponseCookie = "audown-download-response";

function finishResultsHide() {
    resultsHideTimer = 0;
    resultElements.forEach((element) => element.classList.remove("is-fading-out"));
    resetVideoPreview();
    resetTimeRange();
}

function hideResultsImmediately() {
    window.clearTimeout(resultsHideTimer);
    finishResultsHide();
}

function finishLookupButtonHide() {
    lookupHideTimer = 0;
    lookupButton.hidden = true;
    lookupButton.classList.remove("is-fading-out");
    lookupButton.removeAttribute("aria-busy");
}

function hideLookupButtonAnimated() {
    window.clearTimeout(lookupHideTimer);
    lookupButton.disabled = true;
    lookupButton.setAttribute("aria-busy", "true");
    lookupButton.classList.add("is-fading-out");

    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
        finishLookupButtonHide();
        return;
    }

    lookupHideTimer = window.setTimeout(finishLookupButtonHide, 630);
}

function showLookupButton() {
    window.clearTimeout(lookupHideTimer);
    lookupHideTimer = 0;
    lookupButton.classList.remove("is-fading-out");
    lookupButton.disabled = false;
    lookupButton.removeAttribute("aria-busy");
    lookupButton.hidden = false;
}

function animateResultsOut() {
    if (!resultElements.some((element) => !element.hidden)) {
        return;
    }

    resultElements.forEach((element) => {
        if (!element.hidden) {
            element.classList.add("is-fading-out");
        }
    });

    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
        finishResultsHide();
        return;
    }

    window.clearTimeout(resultsHideTimer);
    resultsHideTimer = window.setTimeout(finishResultsHide, 630);
}

function setUrlLoading(loading) {
    formField.classList.toggle("is-loading", loading);
    urlInput.disabled = loading;
    urlInput.setAttribute("aria-busy", String(loading));
    urlSpinner.hidden = !loading;
}

function setUrlError(hasError) {
    urlInputWrap.classList.toggle("is-error", hasError);
}

function showUrlError(message) {
    setUrlError(true);
    showNotice(message);
}

function createDownloadToken() {
    if (window.crypto?.randomUUID) {
        return window.crypto.randomUUID();
    }

    if (window.crypto?.getRandomValues) {
        const bytes = new Uint8Array(16);
        window.crypto.getRandomValues(bytes);
        return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    }

    return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function clearDownloadResponseCookie() {
    document.cookie = `${downloadResponseCookie}=; Path=/; Max-Age=0; SameSite=Lax`;
}

function resetDownloadButton() {
    window.clearTimeout(downloadCompleteResetTimer);
    downloadCompleteResetTimer = 0;
    submitLabel.textContent = "노래 다운로드";
    submitArrow.textContent = "↗";
    submitArrow.hidden = false;
    submitSpinner.hidden = true;
    submitButton.classList.remove("is-complete");
    submitButton.disabled = false;
    submitButton.removeAttribute("aria-busy");
}

function hasDownloadResponseCookie(token) {
    return document.cookie.split(";").some((cookie) => {
        const [name, value] = cookie.trim().split("=");
        return name === downloadResponseCookie && value === token;
    });
}

function finishDownloadResponse(token) {
    if (!hasDownloadResponseCookie(token)) {
        return false;
    }

    window.clearInterval(downloadResponsePollTimer);
    downloadResponsePollTimer = 0;
    clearDownloadResponseCookie();
    form.classList.remove("is-downloading");
    urlInput.disabled = false;
    urlInput.removeAttribute("aria-disabled");
    urlSubmission.disabled = true;
    setTimeRangeDisabled(false);
    submitLabel.textContent = "다운로드 완료!";
    submitArrow.textContent = "✓";
    submitArrow.hidden = false;
    submitSpinner.hidden = true;
    submitButton.classList.add("is-complete");
    submitButton.removeAttribute("aria-busy");
    downloadCompleteResetTimer = window.setTimeout(resetDownloadButton, 5000);
    return true;
}

function waitForDownloadResponse(token) {
    window.clearInterval(downloadResponsePollTimer);
    if (finishDownloadResponse(token)) {
        return;
    }

    downloadResponsePollTimer = window.setInterval(() => {
        finishDownloadResponse(token);
    }, 200);
}

function handleUrlInput() {
    if (downloadCompleteResetTimer) {
        resetDownloadButton();
    }

    if (activeRequest) {
        requestSequence += 1;
        activeRequest.abort();
        activeRequest = null;
        setUrlLoading(false);
        showLookupButton();
    }

    setUrlError(false);
    hideNotice();

    if (!loadedVideoId) {
        return;
    }

    loadedVideoId = "";
    showLookupButton();
    animateResultsOut();
}

function handleLookupClick() {
    if (activeRequest) {
        return;
    }

    setUrlError(false);
    hideNotice();
    const { id } = extractVideoId(urlInput.value);
    if (!id) {
        showUrlError("유튜브 링크 형식 또는 동영상 ID를 확인해주세요.");
        return;
    }

    loadedVideoId = "";
    hideResultsImmediately();
    setUrlLoading(true);
    hideLookupButtonAnimated();
    const sequence = ++requestSequence;
    void loadVideo(id, sequence);
}

async function loadVideo(videoId, sequence) {
    const request = new AbortController();
    activeRequest = request;

    try {
        const video = await fetchVideoDetails(videoId, { signal: request.signal });
        if (sequence !== requestSequence) {
            return;
        }

        setUrlLoading(false);
        setUrlError(false);
        loadedVideoId = videoId;
        lookupButton.removeAttribute("aria-busy");
        showVideoPreview(video);
        setVideoDuration(video.durationSeconds);
        hideNotice();
    } catch (error) {
        if (sequence !== requestSequence || (error.name === "AbortError" && request.signal.aborted)) {
            return;
        }

        setUrlLoading(false);
        showLookupButton();
        resetVideoPreview();
        resetTimeRange();
        const message = error instanceof TypeError
            ? "네트워크 오류로 동영상 정보를 불러오지 못했습니다. 인터넷 연결을 확인해주세요."
            : error.message;
        showUrlError(message || "동영상 정보를 불러오지 못했습니다.");
    } finally {
        if (activeRequest === request) {
            activeRequest = null;
        }
    }
}

const initialError = new URLSearchParams(window.location.search).get("err");
if (initialError) {
    showUrlError(initialError);

    const cleanUrl = new URL(window.location.href);
    cleanUrl.searchParams.delete("err");
    window.history.replaceState(null, "", `${cleanUrl.pathname}${cleanUrl.search}${cleanUrl.hash}`);
}

urlInput.addEventListener("input", handleUrlInput);
urlInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || lookupButton.hidden) {
        return;
    }

    event.preventDefault();
    handleLookupClick();
});
lookupButton.addEventListener("click", handleLookupClick);

form.addEventListener("submit", (event) => {
    if (form.classList.contains("is-downloading") || downloadCompleteResetTimer) {
        event.preventDefault();
        return;
    }

    const { id } = extractVideoId(urlInput.value);
    if (!id || id !== loadedVideoId) {
        event.preventDefault();
        if (!(id && activeRequest)) {
            showNotice("먼저 조회하기를 눌러 영상 정보를 불러와주세요.");
        }
        return;
    }

    syncTimeRangeFormValues();
    hideNotice();
    form.classList.add("is-downloading");
    urlSubmission.value = urlInput.value;
    urlSubmission.disabled = false;
    submitButton.classList.remove("is-complete");
    clearDownloadResponseCookie();
    const downloadToken = createDownloadToken();
    downloadTokenInput.value = downloadToken;
    urlInput.disabled = true;
    urlInput.setAttribute("aria-disabled", "true");
    setTimeRangeDisabled(true);
    submitButton.disabled = true;
    submitButton.setAttribute("aria-busy", "true");
    submitLabel.textContent = "다운로드 중...";
    submitArrow.hidden = true;
    submitSpinner.hidden = false;
    waitForDownloadResponse(downloadToken);
});

window.addEventListener("pagehide", () => {
    window.clearInterval(downloadResponsePollTimer);
    window.clearTimeout(downloadCompleteResetTimer);
});
