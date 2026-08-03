import { describe, expect, it } from "vitest";
import { decodeGppCpassword } from "./gppCpassword";

describe("decodeGppCpassword", () => {
  it("decrypts a real Groups.xml cpassword value (verified against gpp-decrypt)", async () => {
    await expect(decodeGppCpassword(
      "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ",
    )).resolves.toBe("GPPstillStandingStrong2k18");
  });

  it("trims surrounding whitespace before decoding", async () => {
    await expect(decodeGppCpassword(
      "  edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ  ",
    )).resolves.toBe("GPPstillStandingStrong2k18");
  });

  it("returns undefined for input that isn't valid base64/ciphertext", async () => {
    await expect(decodeGppCpassword("not valid base64 at all!!")).resolves.toBeUndefined();
  });

  it("returns undefined for empty input", async () => {
    await expect(decodeGppCpassword("")).resolves.toBeUndefined();
  });
});
