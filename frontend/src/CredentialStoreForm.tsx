import type {RunState} from "./enumerationModel";
import {sourceLabel} from "./enumerationModel";
import type {useCredentialStore} from "./useCredentialStore";

type Store = ReturnType<typeof useCredentialStore>;

export default function CredentialStoreForm({store, result, onCheck}: {
  store: Store; result?: RunState; onCheck: () => void;
}) {
  const busy = !!result && ["starting", "running"].includes(result.status);
  return <>
    {!!store.saved.data?.length && <div className="credStore">
      {store.saved.data.map((item) => <div key={item.id} className="credStoreRow">
        <button className="credStoreFill" onClick={() => store.apply(item)}
          title="이 계정으로 아래 폼을 채웁니다">
          <b>{item.domain ? item.domain + "\\" : ""}{item.username}</b>
          <span>{item.has_secret ? "🔑 비밀번호 저장됨"
            : item.secret_hint ? `힌트: ${item.secret_hint}` : "비밀번호 미저장"}
            {item.source_detail ? ` · ${sourceLabel[item.source_kind]
              || item.source_kind}: ${item.source_detail}`
              : sourceLabel[item.source_kind] ? ` · ${sourceLabel[item.source_kind]}` : ""}
          </span>
        </button>
        <button className="credStoreDelete" onClick={() => void store.remove(item.id)}
          aria-label="자격증명 삭제">삭제</button>
      </div>)}
    </div>}
    <div className="netexecCredForm">
      <input placeholder="도메인 (선택)" value={store.domain}
        onChange={(event) => store.setDomain(event.target.value)} />
      <input placeholder="사용자명" value={store.username}
        onChange={(event) => store.setUsername(event.target.value)} />
      <input type="password" placeholder="비밀번호" value={store.password}
        onChange={(event) => store.setPassword(event.target.value)} />
      <button disabled={!store.username.trim() || busy} onClick={onCheck}>
        {busy ? "확인 중…" : "NetExec으로 확인"}
      </button>
    </div>
    <div className="credSaveBox">
      <div className="netexecCredForm netexecCredForm--save">
        <input placeholder="비밀번호 힌트 (선택)" value={store.hint}
          onChange={(event) => store.setHint(event.target.value)} />
        <button disabled={!store.username.trim() || store.saving}
          onClick={() => void store.save()}>
          {store.saving ? "저장 중…" : "Credential Store에 저장"}
        </button>
      </div>
      <div className="credProvenance">
        <label>출처
          <select value={store.sourceKind}
            onChange={(event) => store.setSourceKind(event.target.value)}>
            <option value="manual">직접 입력</option>
            <option value="share-file">공유 파일</option>
            <option value="web">웹</option>
            <option value="config">설정 파일</option>
            <option value="kerberoast">Kerberoast 크랙</option>
            <option value="reuse">재사용</option>
            <option value="other">기타</option>
          </select>
        </label>
        <input placeholder="출처 상세 (예: WorkShares/config.ini 12번째 줄)"
          value={store.sourceDetail}
          onChange={(event) => store.setSourceDetail(event.target.value)} />
        <label className="credStoreSecretToggle">
          <input type="checkbox" checked={store.storeSecret}
            onChange={(event) => store.setStoreSecret(event.target.checked)} />
          실제 비밀번호도 로컬에 저장 (재사용·명령 자동채움용)
        </label>
      </div>
    </div>
  </>;
}
