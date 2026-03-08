document.addEventListener('DOMContentLoaded', function() {
    // Create lightbox elements if they don't exist
    if (!document.getElementById('yads-lightbox')) {
        const lightbox = document.createElement('div');
        lightbox.id = 'yads-lightbox';
        lightbox.className = 'lightbox-modal';
        lightbox.innerHTML = `
            <span class="lightbox-close">&times;</span>
            <img class="lightbox-content" id="lightbox-img">
        `;
        document.body.appendChild(lightbox);
    }

    const lightbox = document.getElementById('yads-lightbox');
    const lightboxImg = document.getElementById('lightbox-img');
    const closeBtn = document.querySelector('.lightbox-close');

    // Open function
    function openLightbox(src) {
        lightbox.style.display = "block";
        // Small timeout to allow display:block to render before adding opacity class for transition
        setTimeout(() => {
            lightbox.classList.add('show');
        }, 10);
        lightboxImg.src = src;
    }

    // Close function
    function closeLightbox() {
        lightbox.classList.remove('show');
        setTimeout(() => {
            lightbox.style.display = "none";
        }, 300); // Match transition duration
    }

    // Add click listeners to all images with class 'img-clickable'
    // Also support images inside .screenshot-container or .feature-image automatically or manually tagged
    const clickableImages = document.querySelectorAll('.img-clickable, .feature-image img, .screenshot-container img, .hero-image');
    
    clickableImages.forEach(img => {
        img.style.cursor = 'zoom-in';
        img.addEventListener('click', function() {
            openLightbox(this.src);
        });
    });

    // Close listeners
    closeBtn.addEventListener('click', closeLightbox);
    
    // Close on click outside
    lightbox.addEventListener('click', function(e) {
        if (e.target === lightbox) {
            closeLightbox();
        }
    });
    
    // Close on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === "Escape") {
            closeLightbox();
        }
    });
});
