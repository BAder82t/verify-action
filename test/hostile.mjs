// Injection payloads the stub returns in the "hostile" scenario; the tests check that they render inert.
export const HOSTILE = {
  reason: "bad <img src=x onerror=alert(1)> [link](javascript:alert(1)) | col",
  gap: "<script>alert(2)</script> ![img](https://evil.example/t.png) | x",
  kit: "0.1.0 <b>bold</b>",
  reportUrl: "https://evil.example/r) [click](javascript:alert(3)",
  coverageReason: "<img src=y onerror=alert(4)> | [x](javascript:alert(5))",
};
