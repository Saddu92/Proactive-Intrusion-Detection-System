from flask import Flask, request, jsonify
import pandas as pd
import joblib
import os
from preprocessing import preprocess_features

app = Flask(__name__)

# Load model
model = joblib.load('models/your_model.pkl')

@app.route('/predict-csv', methods=['POST'])
def predict_csv():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and file.filename.endswith('.csv'):
        try:
            df = pd.read_csv(file)
            processed_df, original_data = preprocess_features(df.copy())
            predictions = model.predict_proba(processed_df)[:, 1]
            
            return jsonify({
                'predictions': predictions.tolist(),
                'packet_data': original_data.fillna('N/A').to_dict('records')
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Invalid file format'}), 400

# Add other endpoints (/block-ip, /blocked-ips) here...

if __name__ == '__main__':
    app.run(debug=True, port=8000)