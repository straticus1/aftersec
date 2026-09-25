#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

@interface AftersecPhoto : NSObject <AVCapturePhotoCaptureDelegate>
@property(nonatomic, strong) NSData *jpeg;
@property(nonatomic, strong) dispatch_semaphore_t sem;
@end

@implementation AftersecPhoto
- (void)captureOutput:(AVCapturePhotoOutput *)output
didFinishProcessingPhoto:(AVCapturePhoto *)photo
                error:(NSError *)error {
    (void)output;
    if (error == nil) {
        self.jpeg = [photo fileDataRepresentation];
    }
    dispatch_semaphore_signal(self.sem);
}
@end

// Returns 0 and a malloc'd JPEG, 3 when Camera permission is not granted,
// or another non-zero code when capture cannot complete. This does not
// change the system camera indicator.
int aftersec_camera_jpeg(uint8_t **out, int *out_len) {
    @autoreleasepool {
        if (out == NULL || out_len == NULL) {
            return 2;
        }
        *out = NULL;
        *out_len = 0;
        AVAuthorizationStatus status = [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeVideo];
        if (status != AVAuthorizationStatusAuthorized) {
            return 3;
        }
        AVCaptureDevice *device = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
        if (device == nil) {
            return 4;
        }
        NSError *err = nil;
        AVCaptureDeviceInput *input = [AVCaptureDeviceInput deviceInputWithDevice:device error:&err];
        if (input == nil) {
            return 5;
        }
        AVCaptureSession *session = [[AVCaptureSession alloc] init];
        if ([session canSetSessionPreset:AVCaptureSessionPreset640x480]) {
            session.sessionPreset = AVCaptureSessionPreset640x480;
        }
        if (![session canAddInput:input]) {
            return 6;
        }
        [session addInput:input];
        AVCapturePhotoOutput *photos = [[AVCapturePhotoOutput alloc] init];
        if (![session canAddOutput:photos]) {
            return 7;
        }
        [session addOutput:photos];
        [session startRunning];
        AftersecPhoto *delegate = [AftersecPhoto new];
        delegate.sem = dispatch_semaphore_create(0);
        NSDictionary *format = @{AVVideoCodecKey: AVVideoCodecTypeJPEG};
        AVCapturePhotoSettings *settings = [AVCapturePhotoSettings photoSettingsWithFormat:format];
        [photos capturePhotoWithSettings:settings delegate:delegate];
        long waited = dispatch_semaphore_wait(delegate.sem, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC));
        [session stopRunning];
        if (waited != 0 || delegate.jpeg == nil || delegate.jpeg.length == 0 || delegate.jpeg.length > (8 * 1024 * 1024)) {
            return 8;
        }
        *out_len = (int)delegate.jpeg.length;
        *out = malloc((size_t)*out_len);
        if (*out == NULL) {
            return 9;
        }
        memcpy(*out, delegate.jpeg.bytes, (size_t)*out_len);
        return 0;
    }
}
