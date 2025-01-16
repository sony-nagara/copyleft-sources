/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "DrmConnector.h"

namespace aidl::android::hardware::graphics::composer3::impl {
namespace {

static constexpr const float kMillimetersPerInch = 25.4;

}  // namespace

std::unique_ptr<DrmConnector> DrmConnector::create(::android::base::borrowed_fd drmFd,
                                                   uint32_t connectorId) {
    std::unique_ptr<DrmConnector> connector(new DrmConnector(connectorId));

    if (!LoadDrmProperties(drmFd, connectorId, DRM_MODE_OBJECT_CONNECTOR, GetPropertiesMap(),
                           connector.get())) {
        ALOGE("%s: Failed to load connector properties.", __FUNCTION__);
        return nullptr;
    }

    if (!connector->update(drmFd)) {
        return nullptr;
    }

    return connector;
}

bool DrmConnector::update(::android::base::borrowed_fd drmFd) {
    DEBUG_LOG("%s: Loading properties for connector:%" PRIu32, __FUNCTION__, mId);

    drmModeConnector* drmConnector = drmModeGetConnector(drmFd.get(), mId);
    if (!drmConnector) {
        ALOGE("%s: Failed to load connector.", __FUNCTION__);
        return false;
    }

    mStatus = drmConnector->connection;

    mModes.clear();
    for (uint32_t i = 0; i < drmConnector->count_modes; i++) {
        auto mode = DrmMode::create(drmFd, drmConnector->modes[i]);
        if (!mode) {
            ALOGE("%s: Failed to create mode for connector.", __FUNCTION__);
            return false;
        }

        mModes.push_back(std::move(mode));
    }

    drmModeFreeConnector(drmConnector);

    if (mStatus == DRM_MODE_CONNECTED) {
        if (!loadEdid(drmFd)) {
            return false;
        }
    }

    DEBUG_LOG("%s: connector:%" PRIu32 " widthMillimeters:%" PRIu32 " heightMillimeters:%" PRIu32,
              __FUNCTION__, mId, mWidthMillimeters, mHeightMillimeters);

    return true;
}

bool DrmConnector::loadEdid(::android::base::borrowed_fd drmFd) {
    DEBUG_LOG("%s: display:%" PRIu32, __FUNCTION__, mId);

    mWidthMillimeters = 0;
    mHeightMillimeters = 0;

    const uint64_t edidBlobId = mEdidProp.getValue();
    if (edidBlobId == -1) {
        ALOGW("%s: display:%" PRIu32 " does not have EDID.", __FUNCTION__, mId);
        return true;
    }

    auto blob = drmModeGetPropertyBlob(drmFd.get(), edidBlobId);
    if (!blob) {
        ALOGE("%s: display:%" PRIu32 " failed to read EDID blob (%" PRIu64 "): %s", __FUNCTION__,
              mId, edidBlobId, strerror(errno));
        return false;
    }

    const uint8_t* blobStart = static_cast<uint8_t*>(blob->data);
    mEdid = std::vector<uint8_t>(blobStart, blobStart + blob->length);

    drmModeFreePropertyBlob(blob);

    using byte_view = std::basic_string_view<uint8_t>;

    constexpr size_t kEdidDescriptorOffset = 54;
    constexpr size_t kEdidDescriptorLength = 18;

    byte_view edid(mEdid->data(), mEdid->size());
    edid.remove_prefix(kEdidDescriptorOffset);

    byte_view descriptor(edid.data(), kEdidDescriptorLength);
    if (descriptor[0] == 0 && descriptor[1] == 0) {
        ALOGE("%s: display:%" PRIu32 " is missing preferred detailed timing descriptor.",
              __FUNCTION__, mId);
        return -1;
    }

    const uint8_t w_mm_lsb = descriptor[12];
    const uint8_t h_mm_lsb = descriptor[13];
    const uint8_t w_and_h_mm_msb = descriptor[14];

    mWidthMillimeters = w_mm_lsb | (w_and_h_mm_msb & 0xf0) << 4;
    mHeightMillimeters = h_mm_lsb | (w_and_h_mm_msb & 0xf) << 8;

    return true;
}

uint32_t DrmConnector::getWidth() const {
    DEBUG_LOG("%s: connector:%" PRIu32, __FUNCTION__, mId);

    if (mModes.empty()) {
        return 0;
    }
    return mModes[0]->hdisplay;
}

uint32_t DrmConnector::getHeight() const {
    DEBUG_LOG("%s: connector:%" PRIu32, __FUNCTION__, mId);

    if (mModes.empty()) {
        return 0;
    }
    return mModes[0]->vdisplay;
}

int32_t DrmConnector::getDpiX() const {
    DEBUG_LOG("%s: connector:%" PRIu32, __FUNCTION__, mId);

    if (mModes.empty()) {
        return -1;
    }

    const auto& mode = mModes[0];
    if (mWidthMillimeters) {
        const int32_t dpi = static_cast<int32_t>(
            (static_cast<float>(mode->hdisplay) / static_cast<float>(mWidthMillimeters)) *
            kMillimetersPerInch);
        DEBUG_LOG("%s: connector:%" PRIu32 " has dpi-x:%" PRId32, __FUNCTION__, mId, dpi);
        return dpi;
    }

    return -1;
}

int32_t DrmConnector::getDpiY() const {
    DEBUG_LOG("%s: connector:%" PRIu32, __FUNCTION__, mId);

    if (mModes.empty()) {
        return -1;
    }

    const auto& mode = mModes[0];
    if (mHeightMillimeters) {
        const int32_t dpi = static_cast<int32_t>(
            (static_cast<float>(mode->vdisplay) / static_cast<float>(mHeightMillimeters)) *
            kMillimetersPerInch);
        DEBUG_LOG("%s: connector:%" PRIu32 " has dpi-x:%" PRId32, __FUNCTION__, mId, dpi);
        return dpi;
    }

    return -1;
}

float DrmConnector::getRefreshRate() const {
    DEBUG_LOG("%s: connector:%" PRIu32, __FUNCTION__, mId);

    if (!mModes.empty()) {
        const auto& mode = mModes[0];
        return 1000.0f * mode->clock / ((float)mode->vtotal * (float)mode->htotal);
    }

    return -1.0f;
}

}  // namespace aidl::android::hardware::graphics::composer3::impl
