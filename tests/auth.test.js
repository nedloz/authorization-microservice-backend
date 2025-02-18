const request = require("supertest");
const { app } = require("../src/server");

describe("Auth Api", () => {
    let accessToken;
    let refreshToken;

    test("Регистрация нового пользователя", async () => {
        const res = await request(app)
            .post("/auth/register")
            .send({ username: "user1", password: "1234", nick: "testnick" });
        expect(res.statusCode).toBe(201);
        expect(res.body.message).toBe("User created successfully");
    }, 10000);

    test("Ошибка: регистрация с уже занятым ником", async () => {
        const res = await request(app)
            .post("/auth/register")
            .send({ username: "user2", password: "1234", nick: "testnick" });
        expect(res.statusCode).toBe(400);
        expect(res.body.message).toBe("User created successfully");
    }, 10000)

    test("Логин пользователя", async () => {
        const res = await request(app)
            .post("/auth/login")
            .send({ username: "user1", password: "1234" });
        expect(res.StatusCode).toBe(200);
        expect(res.body).toHaveProperty("accesToken");
        expect(res.body).toHaveProperty("refreshToken");
        accessToken = res.body.accessToken;
        refreshToken = res.body.refreshToken;
    }, 10000);

    test("Доступ к защищенному маршруту", async () => {
        const res = await request(app)
            .get("/auth/protected")
            .set("Authorization", `Bearer ${accessToken}`);
        expect(res.statusCode).toBe(200);
        expect(res.body.message).toContain("Hello");
    }, 10000);

    test("Обновление access-токена", async () => {
        const res = await request(app)
            .post("/auth/refresh")
            .send({ refreshToken });
        expect(res.StatusCode).toBe(200);
        expect(res.body).toHaveProperty("accessToken");
    }, 10000);
    
    test("Удаление аккаунта", async () => {
        const res = await request(app)
            .delete("/auth/delete-account")
            .set("Authorization", `Bearer ${accessToken}`)
            .send({ password: "test_password" });
    
        expect(res.statusCode).toBe(200);
        expect(res.body.message).toBe("Аккаунт успешно удалён.");
    });
});

afterAll((done) => {
    if (global.server) {
        global.server.close(done);
    } else {
        done();
    }
});