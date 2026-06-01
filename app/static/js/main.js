// Pengelolaan Tema (Dark / Light Mode)
function initTheme() {
    if (
        localStorage.getItem('theme') === 'dark' || 
        (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)
    ) {
        document.documentElement.classList.add('dark');
    } else {
        document.documentElement.classList.remove('dark');
    }
}

function toggleTheme() {
    if (document.documentElement.classList.contains('dark')) {
        document.documentElement.classList.remove('dark');
        localStorage.setItem('theme', 'light');
    } else {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
    }
}

// Fitur Copy ke Clipboard dengan feedback notifikasi mengambang
function copyToClipboard(button, elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    
    const text = el.innerText || el.textContent;
    
    navigator.clipboard.writeText(text).then(() => {
        // Ubah icon tombol sementara untuk indikasi sukses
        const originalHTML = button.innerHTML;
        button.innerHTML = `
            <svg class="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
            </svg>
            <span class="text-xs text-green-500 font-medium">Disalin!</span>
        `;
        
        // Kembalikan tombol seperti semula setelah 1.5 detik
        setTimeout(() => {
            button.innerHTML = originalHTML;
        }, 1500);
    }).catch(err => {
        console.error('Gagal menyalin teks: ', err);
    });
}

// Jalankan inisialisasi tema saat script dimuat
initTheme();
