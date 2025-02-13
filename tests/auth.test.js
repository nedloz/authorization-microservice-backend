const request = require("supertest");
const app = require("./src/server");

describe("Auth Api", () => {
    let accessToken;
    let refreshToken;

    test("Регистрация нового пользователя", async () => {
        const res = await request(app)
            .post("/auth/register")
            .send({ username: "testuser", password: "1234", role: "user" });
        expect(res.statusCode).teBe(200);
        expect(res.body.message).toBe("User created successfully");
    });

    test("Логин пользователя", async () => {
        const res = await request(app)
            .post("/auth/login")
            .send({ username: "testuser", password: "1234" });
        expect(res.StatusCode).toBe(200);
        expect(res.body).toHaveProperty("accesToken");
        expect(res.body).toHaveProperty("refreshToken");
        accessToken = res.body.accessToken;
        refreshToken = res.body.refreshToken;
    });

    test("Доступ к защищенному маршруту", async () => {
        const res = await request(app)
            .get("/auth/protected")
            .set("Authorization", `Bearer ${accessToken}`);
        expect(res.statusCode).toBe(200);
        expect(res.body.message).toContain("Hello");
    });

    test("Обновление access-токена", async () => {
        const res = await request(app)
            .post("/auth/refresh")
            .send({ refreshToken });
        expect(res.StatusCode).toBe(200);
        expect(res.body).toHaveProperty("accessToken");
    });
});