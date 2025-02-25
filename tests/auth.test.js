const request = require("supertest");
const { app } = require("../src/server");

describe("Auth Api", () => {
    let accessToken;
    let refreshToken;

    test("Регистрация нового пользователя", async () => {
        const res = await request(app)
            .post("/auth/register")
            .send({ email: "user3", password: "1234", username: "testnick1" });
        expect(res.statusCode).toBe(200);
        expect(res.body.message).toBe("User created successfully");
    }, 10000);

    test("Ошибка: регистрация с уже занятой почтой", async () => {
        const res = await request(app)
            .post("/auth/register")
            .send({ email: "user3", password: "1234", username: "test" });
        expect(res.statusCode).toBe(400);
        expect(res.body.error).toBe("email is already taken");
    }, 10000)

    test("Вход по логину и паролю", async () => {
        const res = await request(app)
            .post("/auth/login")
            .send({ email: "user3", password: "1234" });
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty("accessToken");
        expect(res.body).toHaveProperty("refreshToken");
        accessToken = res.body.accessToken;
        refreshToken = res.body.refreshToken;
    }, 10000);

    test("Обновление access-токена", async () => {
        const res = await request(app)
            .post("/auth/refresh")
            .set("Authorization", `Bearer ${refreshToken}`);

        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty("accessToken");
        accessToken = res.body.accessToken;
    }, 10000);
    
    test("Удаление аккаунта", async () => {
        const res = await request(app)
            .delete("/auth/delete-account")
            .set("Authorization", `Bearer ${refreshToken}`)
            .send({  email: "user3", password: "1234" });
    
        expect(res.statusCode).toBe(200);
        expect(res.body.message).toBe("User has been successfully deleted");
    });
});

afterAll((done) => {
    if (global.server) {
        global.server.close(done);
    } else {
        done();
    }
});