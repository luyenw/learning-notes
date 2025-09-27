let articles = [];
let filteredArticles = [];

document.addEventListener('DOMContentLoaded', function() {
    if (window.location.pathname.includes('index.html') || window.location.pathname === '/' || window.location.pathname.endsWith('/')) {
        initHomepage();
    }
});

async function initHomepage() {
    try {
        await loadArticles();
        displayArticles(articles);
        setupSearch();
    } catch (error) {
        console.error('Error initializing homepage:', error);
        displayError('Failed to load articles. Please try again later.');
    }
}

async function loadArticles() {
    try {
        const response = await fetch('articles/index.json');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        articles = data.articles || [];
        filteredArticles = [...articles];

        articles.sort((a, b) => new Date(b.date) - new Date(a.date));
        filteredArticles.sort((a, b) => new Date(b.date) - new Date(a.date));
    } catch (error) {
        console.error('Error loading articles:', error);
        throw error;
    }
}

function displayArticles(articlesToShow) {
    const container = document.getElementById('articlesContainer');
    if (!container) return;

    if (articlesToShow.length === 0) {
        container.innerHTML = '<div class="error">No articles found.</div>';
        return;
    }

    container.innerHTML = articlesToShow.map(article => `
        <a href="article.html?article=${encodeURIComponent(article.filename)}" class="article-card">
            <h3 class="article-card-title">${escapeHtml(article.title)}</h3>
            <p class="article-card-excerpt">${escapeHtml(article.excerpt || '')}</p>
            <div class="article-card-meta">
                <span class="article-date">${formatDate(article.date)}</span>
                <span class="read-more">Read more →</span>
            </div>
        </a>
    `).join('');
}

function setupSearch() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;

    searchInput.addEventListener('input', function(e) {
        const query = e.target.value.toLowerCase().trim();

        if (query === '') {
            filteredArticles = [...articles];
        } else {
            filteredArticles = articles.filter(article =>
                article.title.toLowerCase().includes(query) ||
                (article.excerpt && article.excerpt.toLowerCase().includes(query)) ||
                (article.tags && article.tags.some(tag => tag.toLowerCase().includes(query)))
            );
        }

        displayArticles(filteredArticles);
    });
}

async function loadArticle() {
    const urlParams = new URLSearchParams(window.location.search);
    const articleFilename = urlParams.get('article');

    if (!articleFilename) {
        displayArticleError('No article specified.');
        return;
    }

    try {
        await loadArticles();

        const article = articles.find(a => a.filename === articleFilename);
        if (!article) {
            displayArticleError('Article not found.');
            return;
        }

        document.getElementById('articleTitle').textContent = article.title + ' - Learning Notes';
        document.getElementById('articleTitleHeader').textContent = article.title;
        document.getElementById('articleMeta').innerHTML = `
            <span>Published on ${formatDate(article.date)}</span>
        `;

        const response = await fetch(`articles/${articleFilename}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const markdownContent = await response.text();
        const htmlContent = marked.parse(markdownContent);

        document.getElementById('articleContent').innerHTML = htmlContent;

        if (typeof hljs !== 'undefined') {
            hljs.highlightAll();
        }

    } catch (error) {
        console.error('Error loading article:', error);
        displayArticleError('Failed to load article. Please try again later.');
    }
}

function displayError(message) {
    const container = document.getElementById('articlesContainer');
    if (container) {
        container.innerHTML = `<div class="error">${escapeHtml(message)}</div>`;
    }
}

function displayArticleError(message) {
    const container = document.getElementById('articleContent');
    if (container) {
        container.innerHTML = `<div class="error">${escapeHtml(message)}</div>`;
    }
}

function formatDate(dateString) {
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    } catch (error) {
        return dateString;
    }
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

if (typeof marked !== 'undefined') {
    marked.setOptions({
        highlight: function(code, lang) {
            if (typeof hljs !== 'undefined' && hljs.getLanguage(lang)) {
                try {
                    return hljs.highlight(code, { language: lang }).value;
                } catch (err) {
                    console.warn('Syntax highlighting failed:', err);
                }
            }
            return code;
        },
        breaks: true,
        gfm: true
    });
}