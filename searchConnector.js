const axios = require('axios');
const cheerio = require('cheerio');

async function search(engine, query, limit = 5) {
    switch (engine.toLowerCase()) {
        case 'duckduckgo':
            return await searchDuckDuckGo(query, limit);
        case 'bing':
            return await searchBing(query, limit);
        case 'google':
            return await searchGoogle(query, limit);
        default:
            throw new Error(`Search engine "${engine}" not supported.`);
    }
}

async function searchDuckDuckGo(query, limit) {
    const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
    const { data } = await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const $ = cheerio.load(data);
    const links = [];
    $('.result__url').each((i, el) => {
        if (i < limit) links.push($(el).attr('href'));
    });
    return links;
}

async function searchBing(query, limit) {
    const url = `https://www.bing.com/search?q=${encodeURIComponent(query)}`;
    const { data } = await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const $ = cheerio.load(data);
    const links = [];
    $('li.b_algo h2 a').each((i, el) => {
        if (i < limit) links.push($(el).attr('href'));
    });
    return links;
}

async function searchGoogle(query, limit) {
    const url = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
    const { data } = await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const $ = cheerio.load(data);
    const links = [];
    $('div.yuRUbf > a').each((i, el) => {
        if (i < limit) links.push($(el).attr('href'));
    });
    return links;
}

module.exports = { search };
