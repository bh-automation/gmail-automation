import {
  Badge,
  Card,
  FluentProvider,
  ProgressBar,
  Text,
  Title1,
  webLightTheme,
} from "@fluentui/react-components";
import "./app.css";

const metrics = [
  ["Messages scanned", "128", "last run • 12:54"],
  ["Action candidates", "14", "confidence ≥ 0.85"],
  ["Review queue", "6", "human decision required"],
  ["Mailbox mutations", "0", "dry-run invariant"],
];

export default function App() {
  return (
    <FluentProvider theme={webLightTheme}>
      <main className="page">
        <header className="header">
          <div><Title1>Gmail Automation</Title1><Text>Observe → Decide → Authorize → Execute → Audit → Recover</Text></div>
          <Badge appearance="tint" color="informative">DRY-RUN • SAFE</Badge>
        </header>
        <section className="metrics">
          {metrics.map(([label,value,sub]) => <Card key={label}><Text size={200}>{label}</Text><div className="value">{value}</div><Text size={200}>{sub}</Text></Card>)}
        </section>
        <section className="lower">
          <Card><Title1 as="h2" className="sectionTitle">Decision Pipeline</Title1><div className="pipeline">Gmail → Normalize → Rules → Policy Kernel → Audit/Undo</div><Text size={200}>Classifier has no direct Gmail mutation capability.</Text></Card>
          <Card><Title1 as="h2" className="sectionTitle">Operational Confidence</Title1><div className="confidence"><Text>Idempotency</Text><b>100%</b></div><ProgressBar value={1}/><div className="confidence"><Text>Undo coverage</Text><b>96%</b></div><ProgressBar value={0.96}/></Card>
        </section>
      </main>
    </FluentProvider>
  );
}
