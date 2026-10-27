import { Router, type IRouter } from "express";

const router: IRouter = Router();

router.post("/ipn", async (req, res) => {
  const signature = req.header("x-nowpayments-sig");

  try {
    const upstream = await fetch("http://127.0.0.1:8000/nowpayments/ipn", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(signature ? { "x-nowpayments-sig": signature } : {}),
      },
      body: JSON.stringify(req.body ?? {}),
      signal: AbortSignal.timeout(10_000),
    });

    const body = await upstream.text();
    const contentType = upstream.headers.get("content-type");
    if (contentType) {
      res.setHeader("content-type", contentType);
    }
    return res.status(upstream.status).send(body);
  } catch {
    return res.status(503).json({ status: "payment_receiver_unavailable" });
  }
});

export default router;
