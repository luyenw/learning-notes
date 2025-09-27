# Learning Notes Blog

A simple, elegant static blog built with vanilla HTML, CSS, and JavaScript. Perfect for documenting learning journeys, sharing knowledge, and creating a personal knowledge base.

## ✨ Features

- **Clean, responsive design** - Looks great on all devices
- **Markdown support** - Write articles in Markdown with syntax highlighting
- **Search functionality** - Find articles quickly with client-side search
- **GitHub Pages ready** - Deploy instantly with zero configuration
- **No build process** - Pure static files, no complicated setup
- **Fast and lightweight** - Optimized for performance

## 🚀 Quick Start

1. **Clone or fork this repository**
2. **Enable GitHub Pages** in your repository settings
3. **Start writing!** Add new `.md` files to the `articles/` folder

## 📁 Project Structure

```
learning-notes/
├── index.html          # Homepage with article listing
├── article.html        # Individual article viewer
├── css/
│   └── style.css       # Responsive styling
├── js/
│   ├── main.js         # Blog functionality
│   └── marked.min.js   # Markdown parser
├── articles/
│   ├── index.json      # Article metadata
│   ├── welcome.md      # Sample welcome article
│   └── getting-started.md # Sample tutorial article
└── README.md
```

## ✍️ Adding New Articles

1. **Create a new `.md` file** in the `articles/` folder
2. **Update `articles/index.json`** with article metadata:

```json
{
  "articles": [
    {
      "title": "Your Article Title",
      "filename": "your-article.md",
      "date": "2024-09-27",
      "excerpt": "A brief description of your article content...",
      "tags": ["tag1", "tag2", "tag3"]
    }
  ]
}
```

3. **Commit and push** - Your article will be live instantly!

## 🎨 Customization

### Styling
Edit `css/style.css` to customize colors, fonts, and layout. The CSS uses CSS custom properties (variables) for easy theming.

### Site Information
Update the site title and description in both `index.html` and `article.html`.

### Configuration
Modify `js/main.js` to customize search behavior, date formatting, or add new features.

## 🌐 Deployment

### GitHub Pages (Recommended)
1. Go to your repository settings
2. Navigate to "Pages" in the sidebar
3. Select "Deploy from a branch"
4. Choose "main" branch and "/ (root)" folder
5. Your site will be available at `https://yourusername.github.io/repository-name`

### Other Platforms
This static site works on any hosting platform:
- **Netlify** - Drag and drop deployment
- **Vercel** - Git-based deployment
- **Surge.sh** - Command-line deployment
- **Any web server** - Just upload the files

## 🛠️ Technology Stack

- **HTML5** - Semantic structure
- **CSS3** - Modern styling with Grid and Flexbox
- **Vanilla JavaScript** - No frameworks, pure performance
- **Marked.js** - Markdown parsing
- **Highlight.js** - Syntax highlighting for code blocks

## 📱 Browser Support

Works on all modern browsers including:
- Chrome/Edge 88+
- Firefox 85+
- Safari 14+
- Mobile browsers

## 🤝 Contributing

Contributions welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests
- Share your customizations

## 📄 License

MIT License - feel free to use this project for personal or commercial purposes.

---

**Happy blogging!** 🎉

Built with ❤️ for the learning community.
