# ThreatCast - minimal offline demo (Streamlit). Reuses the notebook pipeline.
# Run:  pip install streamlit torch scikit-learn matplotlib pandas
#       streamlit run app.py
import streamlit as st
import numpy as np, pandas as pd, io
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, confusion_matrix, precision_recall_curve

st.set_page_config(page_title="ThreatCast", layout="wide")

# ---------------- pipeline (same logic as the notebook) ----------------
def load_clean(df):
    df.columns=[c.strip() for c in df.columns]
    def find(cs):
        for c in df.columns:
            if any(k in c.lower().replace("_"," ") for k in cs): return c
    lab=find(["label"]); tc=find(["timestamp","time"]); dp=find(["dst port","destination port","dport"])
    df["_y"]=(~df[lab].astype(str).str.strip().str.lower().str.startswith("benign")).astype(int)
    df["_t"]=pd.to_datetime(df[tc],errors="coerce",dayfirst=True)
    df=df.dropna(subset=["_t"]).replace([np.inf,-np.inf],np.nan).sort_values("_t")
    return df,dp

def aggregate(df,dp,W):
    df["_bin"]=((df["_t"]-df["_t"].min()).dt.total_seconds()//W).astype(int)
    cands=["Flow Duration","Tot Fwd Pkts","Total Fwd Packets","Tot Bwd Pkts","Total Backward Packets",
      "Fwd Pkt Len Mean","Fwd Packet Length Mean","Flow Byts/s","Flow Bytes/s","Flow Pkts/s",
      "Flow Packets/s","SYN Flag Cnt","SYN Flag Count","Pkt Len Mean","Packet Length Mean",
      "Fwd IAT Mean","Bwd IAT Mean","Init Fwd Win Byts","Init_Win_bytes_forward"]
    fs=[c for c in cands if c in df.columns]
    for c in fs: df[c]=pd.to_numeric(df[c],errors="coerce")
    g=df.groupby("_bin"); agg=g[fs].mean(); agg["flow_count"]=g.size()
    if dp: agg["uniq_dport"]=g[dp].nunique()
    agg["ybin"]=(g["_y"].mean()>0).astype(int)
    agg=agg.sort_index().reset_index()
    cols=[c for c in agg.columns if c not in ["_bin","ybin"]]
    return agg,cols

def build(agg,cols,H,K):
    a=np.nan_to_num(agg[cols].values.astype(float)); X,Y,last=[],[],[]
    for i in range(H-1,len(agg)-K):
        X.append(a[i-H+1:i+1]); Y.append(int(agg["ybin"].values[i+K])); last.append(a[i])
    return np.array(X),np.array(Y),np.array(last)

def split3(X,Y,B,ftr=.6,fva=.15):
    n=len(X); a=int(n*ftr); b=int(n*(ftr+fva))
    return (X[:a],Y[:a],B[:a]),(X[a:b],Y[a:b],B[a:b]),(X[b:],Y[b:],B[b:])

def fit_baseline(Btr,Ytr,Bte):
    sc=StandardScaler().fit(Btr)
    m=LogisticRegression(max_iter=1000,class_weight="balanced").fit(np.nan_to_num(sc.transform(Btr)),Ytr)
    return m.predict_proba(np.nan_to_num(sc.transform(Bte)))[:,1]

def fit_temporal(Xtr,Ytr,Xte,epochs=12):
    try:
        import torch,torch.nn as nn; torch.manual_seed(0)
        f=Xtr.shape[-1]; mu=Xtr.reshape(-1,f).mean(0); sd=Xtr.reshape(-1,f).std(0)+1e-6
        T=lambda A: torch.nan_to_num(torch.tensor((A-mu)/sd,dtype=torch.float32))
        xtr,xte=T(Xtr),T(Xte); ytr=torch.tensor(Ytr,dtype=torch.float32)
        class L(nn.Module):
            def __init__(s,f): super().__init__(); s.l=nn.LSTM(f,32,batch_first=True); s.fc=nn.Linear(32,1)
            def forward(s,x): o,_=s.l(x); return s.fc(o[:,-1,:]).squeeze(1)
        m=L(f); pw=torch.tensor([(Ytr==0).sum()/max((Ytr==1).sum(),1)],dtype=torch.float32)
        opt=torch.optim.Adam(m.parameters(),lr=1e-2); lf=nn.BCEWithLogitsLoss(pos_weight=pw)
        for _ in range(epochs): m.train(); opt.zero_grad(); lf(m(xtr),ytr).backward(); opt.step()
        m.eval()
        with torch.no_grad(): return np.nan_to_num(torch.sigmoid(m(xte)).numpy()),"LSTM (PyTorch)"
    except Exception as e:
        from sklearn.neural_network import MLPClassifier
        sc=StandardScaler().fit(Xtr.reshape(len(Xtr),-1))
        g=lambda A: np.nan_to_num(sc.transform(A.reshape(len(A),-1)))
        m=MLPClassifier(hidden_layer_sizes=(64,),max_iter=400,random_state=0).fit(g(Xtr),Ytr)
        return m.predict_proba(g(Xte))[:,1],"MLP (fallback)"

# ---------------- UI ----------------
st.title("ThreatCast - Network Attack Forecasting (offline demo)")
st.caption("SIH26153 - Team Foresight | runs fully offline, no cloud")
with st.sidebar:
    st.header("Settings")
    csv_path=st.text_input("Path to CIC-IDS-2018 day CSV","02-28-2018.csv",
                           help="Local file path. No size limit - read directly from disk.")
    max_rows=st.number_input("Max rows to read (0 = all)",0,20000000,300000,50000,
                             help="Cap rows for speed on huge files. 0 reads the whole file.")
    W=st.number_input("Window seconds",5,60,10,5)
    H=st.number_input("History windows",3,20,8,1)
    K=st.number_input("Forecast ahead (windows)",1,24,3,1)
    fpr=st.slider("Operating false-alarm rate",0.01,0.20,0.05,0.01)
    run=st.button("Run forecast", type="primary")

import os
if run and csv_path.strip():
    if not os.path.exists(csv_path.strip()):
        st.error(f"File not found: {csv_path}. Put the CSV next to this app or paste its full path."); st.stop()
    with st.spinner("Reading traffic, training model, forecasting..."):
        _nr=None if max_rows==0 else int(max_rows)
        df=pd.read_csv(csv_path.strip(),low_memory=False,nrows=_nr); df,dp=load_clean(df)
        agg,cols=aggregate(df,dp,W); X,Y,B=build(agg,cols,H,K)
        (Xtr,Ytr,Btr),(Xva,Yva,Bva),(Xte,Yte,Bte)=split3(X,Y,B)
        if Ytr.sum()==0 or Yte.sum()==0:
            st.error("Attacks fall on one side of the time split. Try another day CSV or a smaller window."); st.stop()
        pb=fit_baseline(Btr,Ytr,Bte); pt,name=fit_temporal(Xtr,Ytr,Xte)
        pv=fit_temporal(Xtr,Ytr,Xva)[0]
        negs=(Yva==0).sum(); thr=1.0
        for t in np.unique(pv)[::-1]:
            if ((pv>=t)&(Yva==0)).sum()/max(negs,1)>fpr: continue
            thr=t; break
        prauc_t=average_precision_score(Yte,pt); prauc_b=average_precision_score(Yte,pb)
        pr,rc,th=precision_recall_curve(Yva,pv); bf=float(th[np.argmax(2*pr*rc/(pr+rc+1e-9))]) if len(th) else .5
        pred=(pt>=bf).astype(int); f1=f1_score(Yte,pred)

    if _nr is not None:
        st.warning("You are reading only the first "+str(_nr)+" rows. For the real result set 'Max rows to read' = 0 (read all).")
    c1,c2,c3,c4=st.columns(4)
    c1.metric("PR-AUC (ThreatCast)",f"{prauc_t:.2f}",f"{prauc_t-prauc_b:+.2f} vs baseline")
    c2.metric("PR-AUC (baseline)",f"{prauc_b:.2f}")
    c3.metric("F1 (best threshold)",f"{f1:.2f}")
    c4.metric("Forecast horizon",f"{K*W}s ahead")

    fig,ax=plt.subplots(figsize=(11,3),dpi=130); ax.set_facecolor("#0B1E3B"); fig.patch.set_facecolor("#0B1E3B")
    tx=np.arange(len(Yte))
    ax.plot(tx,pt,color="#38BDF8",lw=2,label=f"ThreatCast ({name})")
    ax.plot(tx,pb,color="#F59E0B",lw=1.4,ls="--",label="baseline")
    ax.fill_between(tx,0,1,where=(Yte==1),color="#EF4444",alpha=0.18,label="actual attack")
    ax.set_ylim(0,1.02); ax.set_xlabel("test window",color="#CBD5E1"); ax.set_ylabel("infiltration prob.",color="#CBD5E1")
    ax.tick_params(colors="#8CA3BF"); [s.set_color("#274060") for s in ax.spines.values()]
    ax.legend(fontsize=8,framealpha=0,labelcolor="#E2E8F0",loc="upper left")
    st.pyplot(fig)

    st.subheader("Top-risk windows (why they were flagged)")
    benign=np.nan_to_num(Btr[Ytr==0].mean(0)) if (Ytr==0).any() else np.zeros(Btr.shape[1])
    order=list(np.argsort(-pt)[:8]); rows=[]
    for j in order:
        j=int(j); cur=Bte[j]; z=np.abs((cur-benign)/(np.abs(benign)+1e-6))
        top=[cols[k] for k in np.argsort(-z)[:3]]
        rows.append({"window":j,"attack prob":round(float(pt[j]),3),
                     "actual":"attack" if Yte[j]==1 else "benign","top driving features":", ".join(top)})
    st.table(pd.DataFrame(rows))
    st.caption("Evaluation is leakage-free: earlier traffic trains, later traffic tests, threshold tuned on validation only.")
elif run:
    st.warning("Please enter a valid CSV path in the sidebar first.")
else:
    st.info("Enter the path to a CIC-IDS-2018 day CSV in the sidebar and click **Run forecast**. Runs fully offline - the file is read locally.")