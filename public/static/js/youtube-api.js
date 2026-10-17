import { YOUTUBE_API_KEY } from "./config.js";

const videoIdPattern = /^[A-Za-z0-9_-]{11}$/;

export function extractVideoId(rawUrl) {
  const inputUrl = rawUrl.trim();
  if (
    inputUrl !== rawUrl ||
    !(
      inputUrl.startsWith("https://www.youtube.com/") ||
      inputUrl.startsWith("https://youtu.be/")
    )
  ) {
    return { id: "", recognized: false };
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(inputUrl);
  } catch {
    return { id: "", recognized: false };
  }

  let id = "";
  if (
    parsedUrl.hostname === "www.youtube.com" &&
    parsedUrl.pathname === "/watch"
  ) {
    id = parsedUrl.searchParams.get("v") || "";
  } else if (parsedUrl.hostname === "www.youtube.com") {
    const pathParts = parsedUrl.pathname.split("/").filter(Boolean);
    if (["shorts", "embed", "live", "v"].includes(pathParts[0])) {
      id = pathParts[1] || "";
    }
  } else if (parsedUrl.hostname === "youtu.be") {
    id = parsedUrl.pathname.split("/").filter(Boolean)[0] || "";
  } else {
    return { id: "", recognized: false };
  }

  return { id: videoIdPattern.test(id) ? id : "", recognized: true };
}

export function parseIsoDuration(duration) {
  const match =
    /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(
      duration,
    );
  if (!match || (!duration.includes("T") && !match[1])) {
    throw new Error("동영상 길이 정보를 해석할 수 없습니다.");
  }

  const days = Number(match[1] || 0);
  const hours = Number(match[2] || 0);
  const minutes = Number(match[3] || 0);
  const seconds = Number(match[4] || 0);
  const total = Math.floor(
    days * 86400 + hours * 3600 + minutes * 60 + seconds,
  );
  if (!Number.isSafeInteger(total) || total <= 0) {
    throw new Error("동영상 길이를 확인할 수 없습니다.");
  }
  return total;
}

function apiErrorMessage(response, payload) {
  const reasons = payload?.error?.errors?.map((item) => item.reason) || [];
  const reason = reasons[0] || "";

  if (reason === "videoNotFound" || response.status === 404) {
    return "동영상을 찾을 수 없습니다. 링크를 확인해주세요.";
  }
  if (reason === "videoChartNotFound") {
    return "요청한 동영상 정보를 사용할 수 없습니다.";
  }
  if (reason === "keyInvalid") {
    return "YouTube Data API 키가 올바르지 않습니다.";
  }
  if (reason === "quotaExceeded" || reason === "dailyLimitExceeded") {
    return "YouTube Data API 일일 사용량을 초과했습니다.";
  }
  if (reason === "accessNotConfigured") {
    return "Google Cloud에서 YouTube Data API v3를 사용 설정해주세요.";
  }
  if (response.status === 403 && reason === "forbidden") {
    return "이 동영상 정보를 조회할 권한이 없습니다.";
  }
  if (response.status === 403) {
    return "YouTube Data API 요청이 거부되었습니다. API 키와 사용량을 확인해주세요.";
  }
  if (response.status === 400) {
    return "동영상 정보를 요청할 수 없습니다. 링크를 확인해주세요.";
  }

  return "동영상 정보를 불러오지 못했습니다. 잠시 후 다시 시도해주세요.";
}

export async function fetchVideoDetails(
  videoId,
  { signal, apiKey = YOUTUBE_API_KEY } = {},
) {
  if (!apiKey) {
    throw new Error("YouTube Data API 키가 빌드 설정에 없습니다.");
  }

  const params = new URLSearchParams({
    part: "snippet,contentDetails",
    id: videoId,
    key: apiKey,
  });
  const response = await fetch(
    `https://www.googleapis.com/youtube/v3/videos?${params}`,
    { signal },
  );
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(apiErrorMessage(response, payload));
  }

  const video = payload.items?.[0];
  if (!video) {
    throw new Error(
      "동영상을 찾을 수 없습니다. 비공개 또는 삭제된 영상일 수 있습니다.",
    );
  }

  const title = video.snippet?.title?.trim();
  if (!title) {
    throw new Error("동영상 제목을 불러오지 못했습니다.");
  }

  const thumbnailUrl = ["maxres", "medium", "high", "standard", "default"]
    .map((quality) => video.snippet?.thumbnails?.[quality]?.url)
    .find((url) => typeof url === "string" && url !== "") || "";

  return {
    durationSeconds: parseIsoDuration(video.contentDetails?.duration || ""),
    title,
    thumbnailUrl,
  };
}
