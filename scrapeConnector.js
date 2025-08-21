const express = require('express');
const markdownIt = require('markdown-it');
const puppeteer = require('puppeteer');

const app = express();
app.use(express.json());

const md = new markdownIt();

const scrapeWithPuppeteer = async (url) => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();

  await page.goto(url, { waitUntil: 'networkidle2', timeout: 0 });

  const result = await page.evaluate(() => {
    const title = document.querySelector('h1')?.innerText || document.title;

    const paragraphs = Array.from(document.querySelectorAll('p')).map(p => p.innerText.trim()).filter(Boolean);
    const headings = Array.from(document.querySelectorAll('h2, h3')).map(h => h.innerText.trim());

    let sections = [];

    let current = { heading: 'Introduction', content: '' };

    paragraphs.forEach((para, i) => {
      current.content += para + '\n\n';
    });

    if (current.content) {
      sections.push(current);
    }

    return {
      title,
      sections,
    };
  });

  await browser.close();
  return result;
};

module.exports = { scrapeWithPuppeteer };
