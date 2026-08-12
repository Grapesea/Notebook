(function () {
  "use strict";

  var lightbox;
  var lightboxImage;
  var lightboxCaption;
  var previouslyFocused;

  function createLightbox() {
    if (lightbox) return;

    lightbox = document.createElement("div");
    lightbox.className = "image-lightbox";
    lightbox.setAttribute("role", "dialog");
    lightbox.setAttribute("aria-modal", "true");
    lightbox.setAttribute("aria-label", "图片预览");
    lightbox.setAttribute("aria-hidden", "true");
    lightbox.innerHTML =
      '<button class="image-lightbox__close" type="button" aria-label="关闭图片预览">&times;</button>' +
      '<figure class="image-lightbox__figure">' +
      '<img class="image-lightbox__image" alt="">' +
      '<figcaption class="image-lightbox__caption"></figcaption>' +
      "</figure>";

    document.body.appendChild(lightbox);
    lightboxImage = lightbox.querySelector(".image-lightbox__image");
    lightboxCaption = lightbox.querySelector(".image-lightbox__caption");

    lightbox.querySelector(".image-lightbox__close").addEventListener("click", closeLightbox);
    lightbox.addEventListener("click", function (event) {
      if (event.target === lightbox) closeLightbox();
    });
  }

  function openLightbox(image) {
    createLightbox();
    previouslyFocused = document.activeElement;

    lightboxImage.src = image.currentSrc || image.src;
    lightboxImage.alt = image.alt || "放大的图片";
    lightboxCaption.textContent = image.alt || "";
    lightboxCaption.hidden = !image.alt;

    lightbox.classList.add("is-open");
    lightbox.setAttribute("aria-hidden", "false");
    document.documentElement.classList.add("image-lightbox-open");
    lightbox.querySelector(".image-lightbox__close").focus();
  }

  function closeLightbox() {
    if (!lightbox || !lightbox.classList.contains("is-open")) return;

    lightbox.classList.remove("is-open");
    lightbox.setAttribute("aria-hidden", "true");
    document.documentElement.classList.remove("image-lightbox-open");
    lightboxImage.removeAttribute("src");

    if (previouslyFocused && document.contains(previouslyFocused)) {
      previouslyFocused.focus();
    }
  }

  document.addEventListener("click", function (event) {
    var image = event.target.closest(".md-content img");
    if (!image || image.closest(".image-lightbox") || image.dataset.noZoom !== undefined) return;

    event.preventDefault();
    openLightbox(image);
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeLightbox();
  });
})();
