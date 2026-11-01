import React, { useState } from 'react';
import { Shell } from './components/layout/Shell';
import { OverviewView } from './views/OverviewView';
import { AssessmentLaunchView } from './views/AssessmentLaunchView';
import { AssetInventoryView } from './views/AssetInventoryView';
import { FindingsTriageView } from './views/FindingsTriageView';
import { AssessmentDiffView } from './views/AssessmentDiffView';
import { ReportsView } from './views/ReportsView';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState('overview');
  const [navigationMeta, setNavigationMeta] = useState<any>(null);

  const handleNavigate = (tab: string, meta?: any) => {
    setCurrentTab(tab);
    if (meta) {
      setNavigationMeta(meta);
    }
  };

  return (
    <Shell currentTab={currentTab} onTabChange={setCurrentTab}>
      {currentTab === 'overview' && <OverviewView onNavigate={handleNavigate} />}
      {currentTab === 'assessments' && <AssessmentLaunchView onNavigate={handleNavigate} />}
      {currentTab === 'inventory' && <AssetInventoryView onNavigate={handleNavigate} />}
      {currentTab === 'findings' && (
        <FindingsTriageView 
          onNavigate={handleNavigate} 
          initialTargetIp={navigationMeta?.targetIp} 
        />
      )}
      {currentTab === 'diff' && <AssessmentDiffView />}
      {currentTab === 'reports' && (
        <ReportsView initialAssessmentId={navigationMeta?.assessmentId} />
      )}
    </Shell>
  );
};

export default App;
