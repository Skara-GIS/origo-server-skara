var conf = require('../conf/config');
var url = require('url');
var dns = require('dns');

var pendingAuths = Object.create(null);

var DEFAULT_TIMEOUT = conf.iotproxyyggio?.timeout || 10000;
var configMB = conf.iotproxyyggio?.maxResponseSizeMB || 1;
var MAX_RESPONSE_SIZE = configMB * 1024 * 1024;

var tokenCache = {
  data: Object.create(null),

  get: function (key) {
    var cached = this.data[key];
    if (cached && cached.expiresAt > Date.now() + 5000) return cached;
    if (cached) delete this.data[key];
    return null;
  },

  set: function (key, value) {
    this.data[key] = value;
  },

  delete: function (key) {
    delete this.data[key];
  },

  clean: function () {
    var now = Date.now();
    Object.keys(this.data).forEach((key) => {
      var item = this.data[key];
      if (!item || item.expiresAt <= now) delete this.data[key];
    });
  }
};

setInterval(() => tokenCache.clean(), 60 * 1000);

function customLookup(hostname, options, callback) {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);

    var blocklist = conf.iotproxyyggio?.internalBlocklist || [];

    var shouldBlock = blocklist.some(blockedIp => {
      if (blockedIp === address) return true;
      if (blockedIp.endsWith('.') && address.startsWith(blockedIp)) return true;
      return false;
    });

    if (shouldBlock) {
      return callback(new Error('getaddrinfo ENOTFOUND'));
    }

    callback(null, address, family);
  });
}

module.exports = async function iotProxyYggio(req, res) {
  try {
    var parsedUrl;

    try {
      parsedUrl = url.parse(decodeURI(req.url), true);
    } catch {
      return res.status(400).json({ error: 'Bad Request' });
    }

    var q = (parsedUrl.query.q || '').toString().trim();
    if (!q) return res.status(400).json({ error: 'Missing parameter' });

    if (!conf.iotproxyyggio || !Array.isArray(conf.iotproxyyggio.services)) {
      return res.status(500).json({ error: 'Configuration unavailable' });
    }

    var service = conf.iotproxyyggio.services.find((s) => s.name === q);
    if (!service) return res.status(404).json({ error: 'Not found' });

    if (!service.url.toLowerCase().startsWith('https://')) {
      return res.status(400).json({ error: 'Invalid protocol' });
    }

    return await doGet(req, res, service);

  } catch (err) {
    console.error('Proxy request failed');
    return res.status(500).json({ error: 'Internal server error' });
  }
};

async function doGet(req, res, configOptions) {
  var attempts = 0;
  var maxAttempts = 2;

  while (attempts < maxAttempts) {
    attempts++;

    try {
      var headers = { Accept: 'application/json' };
      var authOptions = await getAuthOptions(configOptions.auth);
      if (authOptions?.headers) Object.assign(headers, authOptions.headers);

      var response = await fetchWithTimeout(
        configOptions.url,
        {
          method: 'GET',
          headers,
          redirect: 'manual'
        },
        configOptions.timeout || DEFAULT_TIMEOUT
      );

      if (response.status === 401 && attempts < maxAttempts && configOptions.auth) {
        var cacheKey = [configOptions.auth.token_url, configOptions.auth.user].join('|');
        tokenCache.delete(cacheKey);
        continue;
      }

      if (!response.ok) {
        return res.status(response.status).json({ error: 'Upstream HTTP error' });
      }

      var parsedBody = await safeJson(response, MAX_RESPONSE_SIZE);
      if (!parsedBody) return res.status(502).json({ error: 'Empty upstream response' });

      var geojson = createGeojson(parsedBody, configOptions);
      return res.json(geojson);

    } catch (err) {
      if (err.name === 'AbortError') return res.status(504).json({ error: 'Upstream timeout' });
      return res.status(502).json({ error: 'Fetch failed' });
    }
  }
}

async function getAuthOptions(authConfig) {
  if (!authConfig) return null;

  if (authConfig.token_url) {
    var tokenObject = await getCachedToken(authConfig);
    if (!tokenObject?.token) throw new Error('Auth token failed');
    return { headers: { Authorization: 'Bearer ' + tokenObject.token } };
  }

  if (authConfig.token) {
    return { headers: { Authorization: 'Bearer ' + authConfig.token } };
  }

  return null;
}

async function getCachedToken(authConfig) {
  var cacheKey = [authConfig.token_url, authConfig.user].join('|');
  var cached = tokenCache.get(cacheKey);
  if (cached) return cached;

  if (pendingAuths[cacheKey]) return pendingAuths[cacheKey];

  pendingAuths[cacheKey] = fetchToken(authConfig);

  try {
    var tokenObject = await pendingAuths[cacheKey];
    if (tokenObject) tokenCache.set(cacheKey, tokenObject);
    return tokenObject;
  } finally {
    delete pendingAuths[cacheKey];
  }
}

async function fetchToken(authConfig) {
  var response = await fetchWithTimeout(
    authConfig.token_url,
    {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: authConfig.user,
        password: authConfig.pass
      }),
      redirect: 'manual'
    },
    DEFAULT_TIMEOUT
  );

  if (!response.ok) return null;

  var body = await safeJson(response, 1024 * 1024);
  var token = body?.jwt || body?.token || body?.access_token;
  if (!token) return null;

  var expiresAt = Date.now() + 3600 * 1000;

  try {
    var parts = token.split('.');
    if (parts.length === 3) {
      var payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      if (payload?.exp) expiresAt = payload.exp * 1000;
    }
  } catch {}

  return { token, expiresAt };
}

async function fetchWithTimeout(url, options, timeoutMs) {
  var controller = new AbortController();
  var timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
      lookup: customLookup
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function safeJson(response, maxSize) {
  var text = await response.text();
  if (!text) return null;

  if (Buffer.byteLength(text, 'utf8') > maxSize) {
    throw new Error('Response too large');
  }
  return JSON.parse(text);
}

function createGeojson(payload, configOptions) {
  var result = {
    type: 'FeatureCollection',
    name: configOptions.title || '',
    features: []
  };

  var entities = Array.isArray(payload) ? payload : [payload];

  entities.forEach((entity) => {
    if (!entity || typeof entity !== 'object') return;

    var coords = buildCoordinates(entity, configOptions);
    if (!coords) return;

    var props = {};
    if (Array.isArray(configOptions.properties)) {
      configOptions.properties.forEach((key) => {
        if (Object.prototype.hasOwnProperty.call(entity, key)) {
          props[key] = entity[key];
        }
      });
    } else {
      props = entity;
    }

    result.features.push({
      type: 'Feature',
      id: entity.id || entity._id,
      geometry: {
        type: 'Point',
        coordinates: coords
      },
      properties: props
    });
  });

  return result;
}

function buildCoordinates(entity, configOptions) {
  var latConfig = configOptions.lat || 'latitude';
  var lonConfig = configOptions.lon || 'longitude';

  var latVal;
  var lonVal;

  if (!Number.isNaN(parseFloat(latConfig)) && !latConfig.toString().includes('.' === false)) {
    latVal = latConfig;
  } else {
    latVal = resolveProperty(entity, latConfig);
  }

  if (!Number.isNaN(parseFloat(lonConfig)) && !lonConfig.toString().includes('.' === false)) {
    lonVal = lonConfig;
  } else {
    lonVal = resolveProperty(entity, lonConfig);
  }

  if (latVal == null || lonVal == null) {
    var possibleArray = entity.coordinates || entity.geometry?.coordinates || entity.position?.coordinates;
    if (Array.isArray(possibleArray) && possibleArray.length >= 2) {
      lonVal = possibleArray[0];
      latVal = possibleArray[1];
    }
  }

  if (latVal == null || lonVal == null) return null;

  var la = parseFloat(latVal);
  var lo = parseFloat(lonVal);

  if (Number.isNaN(la) || Number.isNaN(lo)) return null;

  return [lo, la];
}

function resolveProperty(obj, path) {
  return path.split('.').reduce((acc, k) => acc?.[k], obj);
}