import React from 'react';
import { SecurityProvider, useSecurity } from './context/SecurityContext';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { OverviewView } from './components/views/OverviewView';
import { ThreatDetectionView } from './components/views/ThreatDetectionView';
import { TrafficAnalysisView } from './components/views/TrafficAnalysisView';
import { DetectorHealthView } from './components/views/DetectorHealthView';
import { EventHistoryView } from './components/views/EventHistoryView';
import { SettingsView } from './components/views/SettingsView';

const MainContent: React.FC = () => {
  const { activeTab } = useSecurity();

  const renderActiveView = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewView />;
      case 'threat-detection':
        return <ThreatDetectionView />;
      case 'traffic-analysis':
        return <TrafficAnalysisView />;
      case 'detector-health':
        return <DetectorHealthView />;
      case 'event-history':
        return <EventHistoryView />;
      case 'settings':
        return <SettingsView />;
      default:
        return <OverviewView />;
    }
  };

  return (
    <div className="flex-1 flex flex-col h-screen overflow-hidden bg-[#070b14]">
      <Header />
      <main className="flex-1 overflow-y-auto p-6 bg-gradient-to-b from-[#090e1a] to-[#070b14]">
        <div className="max-w-7xl mx-auto">
          {renderActiveView()}
        </div>
      </main>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <SecurityProvider>
      <div className="flex h-screen w-screen overflow-hidden text-slate-100 bg-[#070b14] font-sans antialiased">
        <Sidebar />
        <MainContent />
      </div>
    </SecurityProvider>
  );
};

export default App;
