#import "coreml_wrapper.h"
#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
#import <string.h>
#import <stdlib.h>

// Helper to convert NSString to C string
static char* nsstring_to_cstring(NSString* str) {
    if (!str) return NULL;
    const char* utf8 = [str UTF8String];
    if (!utf8) return NULL;
    size_t len = strlen(utf8);
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    memcpy(result, utf8, len + 1);
    return result;
}

// Load CoreML model from compiled .mlmodelc directory
CoreMLModelRef coreml_load_model(const char* model_path, char** error_out) {
    @autoreleasepool {
        if (!model_path) {
            if (error_out) {
                *error_out = strdup("model_path is NULL");
            }
            return NULL;
        }

        NSString* path = [NSString stringWithUTF8String:model_path];
        NSURL* modelURL = [NSURL fileURLWithPath:path];

        NSError* error = nil;
        MLModel* model = [MLModel modelWithContentsOfURL:modelURL error:&error];

        if (error) {
            if (error_out) {
                *error_out = nsstring_to_cstring([error localizedDescription]);
            }
            return NULL;
        }

        // Configure for Neural Engine if available
        MLModelConfiguration* config = [[MLModelConfiguration alloc] init];
        if (@available(macOS 10.15, *)) {
            if (coreml_has_neural_engine()) {
                config.computeUnits = MLComputeUnitsAll; // Use Neural Engine + GPU + CPU
            } else {
                config.computeUnits = MLComputeUnitsCPUAndGPU;
            }
        }

        // Reload with configuration
        model = [MLModel modelWithContentsOfURL:modelURL configuration:config error:&error];
        if (error) {
            if (error_out) {
                *error_out = nsstring_to_cstring([error localizedDescription]);
            }
            return NULL;
        }

        // Use CFBridgingRetain for proper manual reference counting
        return (CoreMLModelRef)CFBridgingRetain(model);
    }
}

// Predict anomaly score for a process/network combination
float coreml_predict_anomaly(
    CoreMLModelRef model_ref,
    const char* process_name,
    const char* network_dest,
    int process_id,
    char** error_out
) {
    @autoreleasepool {
        if (!model_ref) {
            if (error_out) *error_out = strdup("model is NULL");
            return -1.0f;
        }

        MLModel* model = (__bridge MLModel*)model_ref;

        // Create input feature provider
        // This is a simplified example - real implementation would:
        // 1. Vectorize process_name and network_dest into embeddings
        // 2. Create proper MLFeatureProvider with all required inputs
        // 3. Match the exact input schema of your trained model

        NSError* error = nil;
        NSString* processNameStr = process_name ? [NSString stringWithUTF8String:process_name] : @"";
        NSString* networkDestStr = network_dest ? [NSString stringWithUTF8String:network_dest] : @"";

        // Create feature dictionary
        NSMutableDictionary* inputDict = [NSMutableDictionary dictionary];

        // Example: Your model might expect these inputs
        // Adjust based on your actual CoreML model schema
        inputDict[@"process_name"] = processNameStr;
        inputDict[@"network_dest"] = networkDestStr;
        inputDict[@"process_id"] = @(process_id);

        // Create MLDictionaryFeatureProvider
        MLDictionaryFeatureProvider* input = [[MLDictionaryFeatureProvider alloc]
            initWithDictionary:inputDict error:&error];

        if (error) {
            if (error_out) *error_out = nsstring_to_cstring([error localizedDescription]);
            return -1.0f;
        }

        // Make prediction
        id<MLFeatureProvider> output = [model predictionFromFeatures:input error:&error];

        if (error) {
            if (error_out) *error_out = nsstring_to_cstring([error localizedDescription]);
            return -1.0f;
        }

        // Extract anomaly score from output
        // Adjust this based on your model's output schema
        MLFeatureValue* anomalyScoreFeature = [output featureValueForName:@"anomaly_score"];
        if (!anomalyScoreFeature) {
            // Try alternate output names
            anomalyScoreFeature = [output featureValueForName:@"output"];
        }

        if (!anomalyScoreFeature) {
            if (error_out) *error_out = strdup("Could not find anomaly_score in model output");
            return -1.0f;
        }

        // Get the score value
        double score = 0.0;
        if (anomalyScoreFeature.type == MLFeatureTypeDouble) {
            score = anomalyScoreFeature.doubleValue;
        } else if (anomalyScoreFeature.type == MLFeatureTypeInt64) {
            score = (double)anomalyScoreFeature.int64Value;
        } else if (anomalyScoreFeature.type == MLFeatureTypeMultiArray) {
            // Handle MultiArray output (common for neural networks)
            MLMultiArray* multiArray = anomalyScoreFeature.multiArrayValue;
            if (multiArray.count > 0) {
                score = [multiArray objectAtIndexedSubscript:0].doubleValue;
            }
        }

        return (float)score;
    }
}

// Free model resources
void coreml_free_model(CoreMLModelRef model_ref) {
    if (model_ref) {
        CFRelease(model_ref);
    }
}

// Check if Apple Neural Engine is available
int coreml_has_neural_engine(void) {
    @autoreleasepool {
        // Neural Engine available on Apple Silicon (M1/M2/M3) Macs
        // Check if we're on ARM64 architecture
        #if defined(__arm64__) || defined(__aarch64__)
            // Further check: Neural Engine available on macOS 11.0+ with Apple Silicon
            if (@available(macOS 11.0, *)) {
                return 1;
            }
        #endif
        return 0;
    }
}

// Get CoreML version information
const char* coreml_version_info(void) {
    @autoreleasepool {
        NSProcessInfo* info = [NSProcessInfo processInfo];
        NSOperatingSystemVersion version = [info operatingSystemVersion];

        NSString* versionStr = [NSString stringWithFormat:@"macOS %ld.%ld.%ld, CoreML available: YES, Neural Engine: %s",
            (long)version.majorVersion,
            (long)version.minorVersion,
            (long)version.patchVersion,
            coreml_has_neural_engine() ? "YES" : "NO"];

        return nsstring_to_cstring(versionStr);
    }
}
