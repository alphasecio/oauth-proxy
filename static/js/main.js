function copyToken() {
    const token = document.getElementById('token').textContent;
    navigator.clipboard.writeText(token).then(() => {
        const btn = document.querySelector('.copy-btn');
        const originalHTML = btn.innerHTML;
        btn.classList.add('copied');
        btn.innerHTML = '<svg fill="white" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
        
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.innerHTML = originalHTML;
        }, 2000);
    });
}
