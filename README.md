# jwt256

Implementation of JWT using AES-256

![jwt](http://jwt.io/img/logo-asset.svg)

## To Use

`yarn add @random-guys/jwt256` or `npm install @random-guys/jwt256`

---

Ensure `JWT_SECRET` and `REDIS_URL` environment variables are set.

## Usage

```ts
import { GetUserAuth, SetUserAuth } from "@random-guys/jwt256";

// creates an encrpted JWT token and saves it in Redis using the user's id.
@httpPost("/signup")
async signup(@request() req: Request, @response() res: Response, @requestBody(), body: SignupDTO) {
  try {
    let user = create(body);
    const token = await SetUserAuth(user._id);
    this.handleSuccess(req, res, { token, user });
  } catch (err) {
    this.handleError(req, res, err);
  }
}

// reads the Authorization header and validates the content with that stored in Redis
@httpPatch("/:phone", GetUserAuth)
async upadateUser(
  @request() req: Request,
  @response() res: Response,
  @requestParam("phone") phone: string,
  @requestBody() body: UpdateProfileDTO
) {
  try {
    const user = await this.userRepo.update({ phone_number: phone }, body);
    this.handleSuccess(req, res, user);
  } catch (err) {
    console.log(err);
    this.handleError(req, res, err);
  }
}

```

## TODO

- Add tests
- Write documentation
