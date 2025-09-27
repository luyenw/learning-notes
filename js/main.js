let articles = [];
let filteredArticles = [];
let allTags = [];
let activeTag = null;

document.addEventListener('DOMContentLoaded', function() {
    if (window.location.pathname.includes('index.html') || window.location.pathname === '/' || window.location.pathname.endsWith('/')) {
        initHomepage();
    }
});

async function initHomepage() {
    try {
        await loadArticles();
        extractTags();
        displayTags();
        displayArticlesByYear(articles);
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

function extractTags() {
    const tagSet = new Set();
    articles.forEach(article => {
        if (article.tags) {
            article.tags.forEach(tag => tagSet.add(tag));
        }
    });
    allTags = Array.from(tagSet).sort();
}

function displayTags() {
    const container = document.getElementById('tagsContainer');
    if (!container) return;

    const allButton = `<button class="tag-filter ${activeTag === null ? 'active' : ''}" onclick="filterByTag(null)">All</button>`;
    const tagButtons = allTags.map(tag =>
        `<button class="tag-filter ${activeTag === tag ? 'active' : ''}" onclick="filterByTag('${escapeHtml(tag)}')">${escapeHtml(tag)}</button>`
    ).join('');

    container.innerHTML = allButton + tagButtons;
}

function filterByTag(tag) {
    activeTag = tag;

    if (tag === null) {
        filteredArticles = [...articles];
    } else {
        filteredArticles = articles.filter(article =>
            article.tags && article.tags.includes(tag)
        );
    }

    displayTags();
    displayArticlesByYear(filteredArticles);
}

function displayArticlesByYear(articlesToShow) {
    const container = document.getElementById('articlesContainer');
    if (!container) return;

    if (articlesToShow.length === 0) {
        container.innerHTML = '<div class="error">No articles found.</div>';
        return;
    }

    const articlesByYear = groupArticlesByYear(articlesToShow);
    const years = Object.keys(articlesByYear).sort((a, b) => b - a);

    container.innerHTML = years.map(year => `
        <div class="year-group">
            <h2 class="year-header">${year}</h2>
            <div class="year-articles">
                ${articlesByYear[year].map(article => `
                    <a href="article.html?article=${encodeURIComponent(article.filename)}" class="article-item">
                        <h3 class="article-title-link">${escapeHtml(article.title)}</h3>
                    </a>
                `).join('')}
            </div>
        </div>
    `).join('');
}

function groupArticlesByYear(articles) {
    const groups = {};
    articles.forEach(article => {
        const year = new Date(article.date).getFullYear();
        if (!groups[year]) {
            groups[year] = [];
        }
        groups[year].push(article);
    });

    Object.keys(groups).forEach(year => {
        groups[year].sort((a, b) => new Date(b.date) - new Date(a.date));
    });

    return groups;
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

        const titleHeader = document.getElementById('articleTitleHeader');
        const metaContainer = document.getElementById('articleMeta');

        titleHeader.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 1rem;">
                <span>${escapeHtml(article.title)}</span>
                <span style="font-size: 1rem; font-weight: 400; color: var(--text-secondary);">${formatDate(article.date)}</span>
            </div>
        `;
        metaContainer.innerHTML = '';

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

function formatDateShort(dateString) {
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            month: 'short',
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