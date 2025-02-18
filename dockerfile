# Используем официальный образ Node.js
FROM node:18

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем package.json и устанавливаем зависимости
COPY package*.json ./

# Удаляем node_modules, чтобы избежать конфликта с платформой
RUN rm -rf node_modules && npm install

# Копируем весь проект в контейнер
COPY . .

# Устанавливаем bcrypt заново (для корректной сборки)
RUN npm rebuild bcrypt --build-from-source

# Открываем порт для сервера
EXPOSE 3000

# Команда по умолчанию (для тестирования)
CMD ["npm", "test"]
