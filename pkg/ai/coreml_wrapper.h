#ifndef COREML_WRAPPER_H
#define COREML_WRAPPER_H

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
#endif

// C interface for CoreML model operations
typedef void* CoreMLModelRef;

#ifdef __cplusplus
extern "C" {
#endif

// Load compiled CoreML model from disk
CoreMLModelRef coreml_load_model(const char* model_path, char** error_out);

// Make prediction using the model
// Returns anomaly score (0.0 to 1.0)
float coreml_predict_anomaly(
    CoreMLModelRef model,
    const char* process_name,
    const char* network_dest,
    int process_id,
    char** error_out
);

// Free model resources
void coreml_free_model(CoreMLModelRef model);

// Check if Neural Engine is available
int coreml_has_neural_engine(void);

// Get CoreML version info
const char* coreml_version_info(void);

#ifdef __cplusplus
}
#endif

#endif // COREML_WRAPPER_H
