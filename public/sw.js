const CACHE_NAME = "audown-shell-v3";
const APP_SHELL = [
    "/manifest.webmanifest",
    "/favicon.ico",
    "/static/css/index.css",
    "/static/js/index.js",
    "/static/js/auth.js",
    "/static/js/notice.js",
    "/static/js/youtube-api.js",
    "/static/js/video-preview.js",
    "/static/js/time-range.js",
    "/static/js/config.js",
    "/static/images/app-icon-192.png",
    "/static/images/app-icon-512.png",
];

function isCacheablePath(pathname) {
    return (
        pathname === "/manifest.webmanifest" ||
        pathname === "/favicon.ico" ||
        pathname.startsWith("/static/")
    );
}

self.addEventListener("install", (event) => {
    event.waitUntil((async () => {
        const cache = await caches.open(CACHE_NAME);
        await cache.addAll(APP_SHELL);
        await self.skipWaiting();
    })());
});

self.addEventListener("activate", (event) => {
    event.waitUntil((async () => {
        const cacheNames = await caches.keys();
        await Promise.all(
            cacheNames
                .filter((name) => name.startsWith("audown-") && name !== CACHE_NAME)
                .map((name) => caches.delete(name)),
        );
        await self.clients.claim();
    })());
});

self.addEventListener("fetch", (event) => {
    const request = event.request;
    if (request.method !== "GET") {
        return;
    }

    const url = new URL(request.url);
    if (url.origin !== self.location.origin || !isCacheablePath(url.pathname)) {
        return;
    }

    event.respondWith(
        fetch(request).then(async (response) => {
            if (response.ok && response.type === "basic") {
                const cache = await caches.open(CACHE_NAME);
                await cache.put(request, response.clone());
            }
            return response;
        }).catch(async () => {
            const cache = await caches.open(CACHE_NAME);
            return cache.match(request);
        }),
    );
});
