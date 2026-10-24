package com.example.data.local

import androidx.room.TypeConverter
import com.example.data.model.AuditAction
import com.example.data.model.AuthorizationStatus
import com.example.data.model.CheckResultStatus
import com.example.data.model.Confidence
import com.example.data.model.EngagementStatus
import com.example.data.model.FindingCategory
import com.example.data.model.FindingStatus
import com.example.data.model.Severity

class Converters {
    @TypeConverter
    fun fromSeverity(value: Severity): String = value.name

    @TypeConverter
    fun toSeverity(value: String): Severity = runCatching { Severity.valueOf(value) }.getOrDefault(Severity.INFORMATIONAL)

    @TypeConverter
    fun fromConfidence(value: Confidence): String = value.name

    @TypeConverter
    fun toConfidence(value: String): Confidence = runCatching { Confidence.valueOf(value) }.getOrDefault(Confidence.CONFIRMED)

    @TypeConverter
    fun fromFindingStatus(value: FindingStatus): String = value.name

    @TypeConverter
    fun toFindingStatus(value: String): FindingStatus = runCatching { FindingStatus.valueOf(value) }.getOrDefault(FindingStatus.AUTOMATED_OBSERVATION)

    @TypeConverter
    fun fromFindingCategory(value: FindingCategory): String = value.name

    @TypeConverter
    fun toFindingCategory(value: String): FindingCategory = runCatching { FindingCategory.valueOf(value) }.getOrDefault(FindingCategory.HTTP_HEADERS)

    @TypeConverter
    fun fromEngagementStatus(value: EngagementStatus): String = value.name

    @TypeConverter
    fun toEngagementStatus(value: String): EngagementStatus = runCatching { EngagementStatus.valueOf(value) }.getOrDefault(EngagementStatus.ACTIVE)

    @TypeConverter
    fun fromAuditAction(value: AuditAction): String = value.name

    @TypeConverter
    fun toAuditAction(value: String): AuditAction = runCatching { AuditAction.valueOf(value) }.getOrDefault(AuditAction.SCAN_INITIATED)

    @TypeConverter
    fun fromAuthorizationStatus(value: AuthorizationStatus): String = value.name

    @TypeConverter
    fun toAuthorizationStatus(value: String): AuthorizationStatus = runCatching { AuthorizationStatus.valueOf(value) }.getOrDefault(AuthorizationStatus.PENDING_VERIFICATION)

    @TypeConverter
    fun fromCheckResultStatus(value: CheckResultStatus): String = value.name

    @TypeConverter
    fun toCheckResultStatus(value: String): CheckResultStatus = runCatching { CheckResultStatus.valueOf(value) }.getOrDefault(CheckResultStatus.PASS)
}
