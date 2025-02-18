const limiter = new Map();
const MAX_ATTEMPTS = 5;
const BLOCK_TIME = 10 * 60 * 1000; // 10 минут

const checkBruteForce = (username) => {
  const now = Date.now();

  if (!limiter.has(username)) {
    limiter.set(username, { attempts: 1, time: now });
    return false;
  }

  const userAttempts = limiter.get(username);

  // Блокировка, если превышено кол-во попыток за короткое время
  if (userAttempts.attempts >= MAX_ATTEMPTS && now - userAttempts.time < BLOCK_TIME) {
    return true;
  }

  // Если блокировка истекла – сбрасываем попытки
  if (now - userAttempts.time > BLOCK_TIME) {
    limiter.set(username, { attempts: 1, time: now });
    return false;
  }

  // Увеличиваем счётчик попыток
  userAttempts.attempts += 1;
  limiter.set(username, userAttempts);
  return false;
};

module.exports = checkBruteForce;
