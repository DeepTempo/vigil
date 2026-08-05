-- Re-key ai_decision_log.agent_id onto the action vocabulary (GH #476)
-- Decision rows are grouped by the action performed, not the role that
-- performed it, and the registry in services/soc_agents.py is now the sole
-- definition of that mapping. Rows written before the registry landed carry
-- role ids (or the daemon's ad-hoc "orchestrator"); rewrite them so the
-- AI-Decisions filter sees one vocabulary.

UPDATE ai_decision_log SET agent_id = CASE agent_id
    WHEN 'investigator'    THEN 'investigation'
    WHEN 'correlator'      THEN 'correlation'
    WHEN 'reporter'        THEN 'reporting'
    WHEN 'responder'       THEN 'response'
    WHEN 'threat_hunter'   THEN 'threat_hunt'
    WHEN 'mitre_analyst'   THEN 'mitre_mapping'
    WHEN 'malware_analyst' THEN 'malware_analysis'
    WHEN 'network_analyst' THEN 'network_analysis'
    WHEN 'auto_responder'  THEN 'auto_response'
    WHEN 'orchestrator'    THEN 'orchestration'
    ELSE agent_id
END
WHERE agent_id IN (
    'investigator', 'correlator', 'reporter', 'responder', 'threat_hunter',
    'mitre_analyst', 'malware_analyst', 'network_analyst', 'auto_responder',
    'orchestrator'
);

COMMENT ON COLUMN ai_decision_log.agent_id IS
    'Action id from services/soc_agents.py:AGENT_IDENTITY (e.g. investigation, '
    'correlation), or orchestration for the autonomous loop''s own decisions';
