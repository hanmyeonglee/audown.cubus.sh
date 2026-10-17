const preview = document.getElementById("video-preview");
const thumbnailWrap = document.getElementById("video-thumbnail-wrap");
const thumbnail = document.getElementById("video-thumbnail");
const title = document.getElementById("video-title");

thumbnail.addEventListener("error", () => {
    thumbnailWrap.hidden = true;
    preview.classList.add("is-thumbnail-missing");
});

export function showVideoPreview(video) {
    title.textContent = video.title;
    title.title = video.title;
    preview.classList.remove("is-thumbnail-missing");
    thumbnailWrap.hidden = !video.thumbnailUrl;
    thumbnail.alt = video.title ? `${video.title} 썸네일` : "동영상 썸네일";

    if (video.thumbnailUrl) {
        thumbnail.src = video.thumbnailUrl;
    } else {
        thumbnail.removeAttribute("src");
        preview.classList.add("is-thumbnail-missing");
    }

    preview.hidden = false;
}

export function resetVideoPreview() {
    preview.hidden = true;
    preview.classList.remove("is-thumbnail-missing");
    thumbnailWrap.hidden = false;
    thumbnail.removeAttribute("src");
    thumbnail.alt = "";
    title.textContent = "";
    title.removeAttribute("title");
}
