from flask import Flask, request, jsonify
from jsonschema import validate, ValidationError

app = Flask(__name__)

ASSESSMENT_SCHEMA = {
    "type": "object",
    "required": [
        "id", "created_at", "metric_id", "metric_configuration",
        "evidence_id", "resource_id", "resource_types",
        "compliance_comment", "target_of_evaluation_id",
        "history_updated_at", "history"
    ],
    "properties": {
        "id": {"type": "string", "format": "uuid"},
        "created_at": {"type": "string", "format": "date-time"},
        "metric_id": {"type": "string", "minLength": 1},
        "metric_configuration": {"type": "object"},
        "compliant": {"type": "boolean"},
        "evidence_id": {"type": "string", "format": "uuid"},
        "resource_id": {"type": "string", "minLength": 1},
        "resource_types": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1
        },
        "compliance_comment": {"type": "string", "minLength": 1},
        "target_of_evaluation_id": {"type": "string", "format": "uuid"},
        "tool_id": {"type": "string", "minLength": 1},
        "history_updated_at": {"type": "string", "format": "date-time"},
        "history": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["evidence_id", "evidence_recorded_at"],
                "properties": {
                    "evidence_id": {"type": "string", "format": "uuid"},
                    "evidence_recorded_at": {"type": "string", "format": "date-time"}
                }
            }
        }
    }
}

@app.route('/assessment-result', methods=['POST'])
def post_assessment_result():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Bad Request"}), 400

    try:
        validate(instance=data, schema=ASSESSMENT_SCHEMA)

        res_id = data.get('id')
        created = data.get('created_at')
        m_id = data.get('metric_id')
        m_cfg = data.get('metric_configuration')
        is_compliant = data.get('compliant')
        ev_id = data.get('evidence_id')
        r_id = data.get('resource_id')
        r_types = data.get('resource_types')
        comp_comment = data.get('compliance_comment')
        toe_id = data.get('target_of_evaluation_id')
        t_id = data.get('tool_id')
        hist_updated = data.get('history_updated_at')
        history_list = data.get('history')

        l2_cfg_keys = list(m_cfg.keys()) if isinstance(m_cfg, dict) else []
        l2_first_res_type = r_types[0] if r_types else None
        
        l2_hist_evidence = None
        l2_hist_time = None
        if history_list and len(history_list) > 0:
            first_record = history_list[0]
            l2_hist_evidence = first_record.get('evidence_id')
            l2_hist_time = first_record.get('evidence_recorded_at')

        return jsonify({
            "status": "success",
            "extracted_id": res_id,
            "first_history_item": l2_hist_evidence
        }), 201

    except ValidationError as e:
        return jsonify({"error": e.message}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)