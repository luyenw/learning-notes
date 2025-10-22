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
        const tagsContainer = document.getElementById('articleTags');

        titleHeader.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 1rem;">
                <span>${escapeHtml(article.title)}</span>
                <span style="font-size: 1rem; font-weight: 400; color: var(--text-secondary);">${formatDate(article.date)}</span>
            </div>
        `;
        metaContainer.innerHTML = '';

        // Display tags
        if (article.tags && article.tags.length > 0) {
            tagsContainer.innerHTML = `
                <div class="tags-list">
                    ${article.tags.map(tag => `<span class="tag-badge">${escapeHtml(tag)}</span>`).join('')}
                </div>
            `;
        }

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

        // Display related articles
        displayRelatedArticles(article);

    } catch (error) {
        console.error('Error loading article:', error);
        displayArticleError('Failed to load article. Please try again later.');
    }
}

// TF-IDF similarity calculation
function calculateTFIDF(articles) {
    const documents = articles.map(a => ({
        id: a.filename,
        text: `${a.title} ${a.tags.join(' ')}`.toLowerCase()
    }));

    const vocabulary = new Set();
    const termFrequency = [];

    documents.forEach(doc => {
        const words = doc.text.split(/\s+/);
        const tf = {};
        words.forEach(word => {
            vocabulary.add(word);
            tf[word] = (tf[word] || 0) + 1;
        });
        termFrequency.push({ id: doc.id, tf, wordCount: words.length });
    });

    const documentFrequency = {};
    vocabulary.forEach(word => {
        documentFrequency[word] = termFrequency.filter(doc => doc.tf[word]).length;
    });

    const tfidf = termFrequency.map(doc => {
        const vector = {};
        Object.keys(doc.tf).forEach(word => {
            const tf = doc.tf[word] / doc.wordCount;
            const idf = Math.log(documents.length / (documentFrequency[word] || 1));
            vector[word] = tf * idf;
        });
        return { id: doc.id, vector };
    });

    return tfidf;
}

function cosineSimilarity(vec1, vec2) {
    const words = new Set([...Object.keys(vec1), ...Object.keys(vec2)]);
    let dotProduct = 0;
    let mag1 = 0;
    let mag2 = 0;

    words.forEach(word => {
        const v1 = vec1[word] || 0;
        const v2 = vec2[word] || 0;
        dotProduct += v1 * v2;
        mag1 += v1 * v1;
        mag2 += v2 * v2;
    });

    if (mag1 === 0 || mag2 === 0) return 0;
    return dotProduct / (Math.sqrt(mag1) * Math.sqrt(mag2));
}

function displayRelatedArticles(currentArticle) {
    const relatedContainer = document.getElementById('relatedArticles');
    if (!relatedContainer) return;

    // Filter articles with common tags
    const articlesWithCommonTags = articles.filter(a =>
        a.filename !== currentArticle.filename &&
        a.tags && currentArticle.tags &&
        a.tags.some(tag => currentArticle.tags.includes(tag))
    );

    if (articlesWithCommonTags.length === 0) {
        relatedContainer.innerHTML = '';
        return;
    }

    // Calculate TF-IDF for similarity
    const allArticles = [currentArticle, ...articlesWithCommonTags];
    const tfidfVectors = calculateTFIDF(allArticles);

    const currentVector = tfidfVectors.find(v => v.id === currentArticle.filename).vector;

    const similarities = articlesWithCommonTags.map(article => {
        const articleVector = tfidfVectors.find(v => v.id === article.filename).vector;
        return {
            article,
            similarity: cosineSimilarity(currentVector, articleVector)
        };
    });

    // Sort by similarity then by date
    similarities.sort((a, b) => {
        if (Math.abs(a.similarity - b.similarity) < 0.01) {
            return new Date(b.article.date) - new Date(a.article.date);
        }
        return b.similarity - a.similarity;
    });

    // Take top 5
    const topRelated = similarities.slice(0, 5);

    if (topRelated.length > 0) {
        relatedContainer.innerHTML = `
            <h2 class="related-title">Related Articles</h2>
            <div class="related-list">
                ${topRelated.map(({ article }) => `
                    <a href="article.html?article=${encodeURIComponent(article.filename)}" class="related-item">
                        <h3 class="related-article-title">${escapeHtml(article.title)}</h3>
                        <div class="related-meta">
                            <span class="related-date">${formatDateShort(article.date)}</span>
                            ${article.tags ? `<span class="related-tags">${article.tags.slice(0, 3).map(t => `#${escapeHtml(t)}`).join(' ')}</span>` : ''}
                        </div>
                    </a>
                `).join('')}
            </div>
        `;
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