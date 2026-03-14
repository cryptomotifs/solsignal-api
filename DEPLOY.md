# Deploy SolSignal API

## Option A: Render.com (Recommended — Free)

### Step 1: Create a GitHub repo for the API
```bash
cd signal_api
git init
git add .
git commit -m "SolSignal API v1.0"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/solsignal-api.git
git push -u origin main
```

### Step 2: Deploy on Render
1. Go to https://render.com and sign up (free, use GitHub login)
2. Click "New +" → "Web Service"
3. Connect your GitHub repo (solsignal-api)
4. Settings:
   - **Name**: solsignal-api
   - **Runtime**: Python
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app:app --host 0.0.0.0 --port $PORT`
   - **Plan**: Free
5. Add Environment Variable:
   - `SIGNAL_WALLET` = your Solana wallet address (for receiving USDC)
6. Click "Create Web Service"

Your API will be live at: `https://solsignal-api.onrender.com`

### Step 3: Verify
```bash
curl https://solsignal-api.onrender.com/health
curl https://solsignal-api.onrender.com/agents
```

---

## Option B: Railway.app (Free tier)

1. Go to https://railway.app, sign up with GitHub
2. "New Project" → "Deploy from GitHub Repo"
3. Select your solsignal-api repo
4. Add variable: `SIGNAL_WALLET` = your wallet
5. Railway auto-detects Python and deploys

---

## Option C: Quick test with ngrok (temporary)

```bash
# Terminal 1: Start API
cd signal_api
pip install -r requirements.txt
uvicorn app:app --port 8402

# Terminal 2: Expose publicly
ngrok http 8402
```

ngrok gives you a URL like `https://abc123.ngrok-free.app`

---

## After Deployment: Get Discovered

1. **awesome-x402**: Submit PR to https://github.com/xpaysh/awesome-x402
   Add under "Data / Analytics":
   ```
   - [SolSignal API](https://your-url.onrender.com) - Arena-calibrated trading signals from 646 AI agents ($0.01-$0.10/call)
   ```

2. **Solana Agent Registry**: Register at https://solana.com/agent-registry

3. **Enable x402**: Set `SIGNAL_WALLET` env var to your Solana address that can receive USDC

---

## Files

```
signal_api/
  app.py              — API server (standalone, no bot dependencies)
  requirements.txt    — Python deps (fastapi, uvicorn, httpx)
  render.yaml         — Render.com deployment config
  Dockerfile          — Docker deployment option
  DEPLOY.md           — This file
  data/
    agent_boost_configs.json  — 646 agent calibration configs (260KB)
    arena_snapshots.db        — 19K token snapshots (6.7MB)
    arena_results.db          — 100K agent scores (19MB)
```

Total deployment size: ~26 MB
