const fieldset = document.getElementById("time-fieldset");
const durationDisplay = document.getElementById("duration-value");
const startRange = document.getElementById("start-range");
const endRange = document.getElementById("end-range");
const startTimeDisplay = document.getElementById("start-time-display");
const endTimeDisplay = document.getElementById("end-time-display");
const rangeSelection = document.getElementById("range-selection");
const submitButton = document.getElementById("submit-button");
const startTimeInput = document.getElementById("startTime");
const endTimeInput = document.getElementById("endTime");

let durationSeconds = 0;

function formatTime(totalSeconds) {
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    return [hours, minutes, seconds]
        .map((part) => String(part).padStart(2, "0"))
        .join(":");
}

function updateValues(changedRange) {
    if (!durationSeconds) {
        return;
    }

    let start = Number(startRange.value);
    let end = Number(endRange.value);
    if (changedRange === startRange && start >= end) {
        start = Math.max(0, end - 1);
    } else if (changedRange === endRange && end <= start) {
        end = Math.min(durationSeconds, start + 1);
    }

    startRange.value = String(start);
    endRange.value = String(end);

    startTimeDisplay.value = formatTime(start);
    endTimeDisplay.value = formatTime(end);
    rangeSelection.style.left = `${(start / durationSeconds) * 100}%`;
    rangeSelection.style.width = `${((end - start) / durationSeconds) * 100}%`;

    const wholeVideoSelected = start === 0 && end === durationSeconds;
    startTimeInput.value = wholeVideoSelected ? "" : formatTime(start);
    endTimeInput.value = wholeVideoSelected ? "" : formatTime(end);
}

startRange.addEventListener("input", () => updateValues(startRange));
endRange.addEventListener("input", () => updateValues(endRange));

export function resetTimeRange() {
    durationSeconds = 0;
    fieldset.disabled = false;
    fieldset.hidden = true;
    submitButton.hidden = true;
    startTimeInput.value = "";
    endTimeInput.value = "";
}

export function setVideoDuration(seconds) {
    durationSeconds = seconds;
    durationDisplay.textContent = formatTime(seconds);

    startRange.min = "0";
    startRange.max = String(seconds);
    startRange.value = "0";
    endRange.min = "0";
    endRange.max = String(seconds);
    endRange.value = String(seconds);

    fieldset.hidden = false;
    submitButton.hidden = false;
    updateValues();
}

export function setTimeRangeDisabled(disabled) {
    fieldset.disabled = disabled;
}

export function syncTimeRangeFormValues() {
    updateValues();
}
