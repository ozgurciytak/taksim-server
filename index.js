const jsonServer = require('json-server');
const server = jsonServer.create();
const path = require('path');
const router = jsonServer.router(path.join(__dirname, 'db.json'));
const middlewares = jsonServer.defaults();
const bcrypt = require('bcryptjs');

const API_KEY = process.env.API_KEY || 'taksim-secret-key-2024';

server.use(middlewares);
server.use(jsonServer.json());

// Şifreleme Middleware (POST ve PATCH istekleri için)
server.use((req, res, next) => {
  if ((req.method === 'POST' || req.method === 'PATCH') && req.url.includes('/users')) {
    if (req.body.password && !req.body.password.startsWith('$2a$')) {
      req.body.password = bcrypt.hashSync(req.body.password, 10);
    }
  }
  next();
});

// 1. Güvenlik Middleware: API Key Kontrolü
server.use((req, res, next) => {
  // Login ve public servisler için API Key kontrolünü atlayabiliriz ama 
  // tam güvenlik için hepsinde zorunlu tutuyoruz.
  const apiKey = req.header('x-api-key');
  
  if (!apiKey || apiKey !== API_KEY) {
    return res.status(403).json({ 
      error: 'Unauthorized access. API Key is missing or invalid.' 
    });
  }
  next();
});

// 2. Özel Login Endpoint (POST)
server.post('/auth/login', (req, res) => {
  const { email, password, role } = req.body;
  const db = router.db;
  
  const user = db.get('users').find({ 
    email: email.toLowerCase(), 
    role: role 
  }).value();

  if (!user) {
    return res.status(401).json({ error: 'Kullanıcı bulunamadı.' });
  }

  // Şifre kontrolü (Hashli veya düz metin - geçiş aşaması için her ikisi)
  const isMatch = bcrypt.compareSync(password, user.password) || password === user.password;

  if (isMatch) {
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } else {
    res.status(401).json({ error: 'Hatalı şifre.' });
  }
});

// 3. Veri Gizleme Middleware (Tüm GET isteklerinde şifreleri gizle)
router.render = (req, res) => {
  let data = res.locals.data;
  
  const maskSensitiveData = (obj) => {
    if (Array.isArray(obj)) {
      return obj.map(item => maskSensitiveData(item));
    } else if (typeof obj === 'object' && obj !== null) {
      const newObj = { ...obj };
      delete newObj.password; // Şifreyi asla dışarı sızdırma
      return newObj;
    }
    return obj;
  };

  res.jsonp(maskSensitiveData(data));
};

server.use(router);

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Taksim Secure Server is running on port ${PORT}`);
  console.log(`API Key protection is ACTIVE.`);
});
