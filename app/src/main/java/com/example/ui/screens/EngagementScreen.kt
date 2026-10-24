package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.model.ApprovedScopeEntity
import com.example.ui.SentinelViewModel
import com.example.ui.components.ScopeStatusChip
import com.example.ui.theme.CyberSlate700
import com.example.ui.theme.CyberSlate800
import com.example.ui.theme.CyberSlate900
import com.example.ui.theme.SentinelCyan
import com.example.ui.theme.SeverityClean
import com.example.ui.theme.SeverityCritical
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun EngagementScreen(
    viewModel: SentinelViewModel,
    modifier: Modifier = Modifier
) {
    val engagements by viewModel.allEngagements.collectAsState()
    val selectedEngId by viewModel.selectedEngagementId.collectAsState()
    val currentAuth by viewModel.currentAuthorization.collectAsState()
    val scopes by viewModel.currentScopes.collectAsState()

    val currentEng = engagements.firstOrNull { it.id == selectedEngId } ?: engagements.firstOrNull()

    var showAddScopeDialog by remember { mutableStateOf(false) }
    var showAuthDialog by remember { mutableStateOf(false) }
    var showNewEngDialog by remember { mutableStateOf(false) }
    var showVerifyDialog by remember { mutableStateOf(false) }
    var showRevokeDialog by remember { mutableStateOf(false) }

    val dateFormat = remember { SimpleDateFormat("MMM dd, yyyy", Locale.US) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag("engagement_screen_list"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Demo / Simulation Warning Banner
        if (currentEng?.isDemo == true) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = SeverityMedium.copy(alpha = 0.15f)),
                    border = androidx.compose.foundation.BorderStroke(1.dp, SeverityMedium),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth().testTag("demo_environment_banner")
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Lock,
                            contentDescription = "Demo Notice",
                            tint = SeverityMedium,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "DEMO / SEED ENVIRONMENT",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = SeverityMedium,
                                letterSpacing = 1.sp
                            )
                            Text(
                                text = "This engagement contains demo fixtures and unverified authorization. For real assessments, create a new engagement with verified written ROA.",
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }

        // 1. Active Engagement Card
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = CyberSlate900),
                border = androidx.compose.foundation.BorderStroke(1.dp, CyberSlate700),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().testTag("active_engagement_card")
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Security,
                                contentDescription = "Security Engagement",
                                tint = SentinelCyan,
                                modifier = Modifier.size(24.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "ACTIVE ENGAGEMENT",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = SentinelCyan,
                                letterSpacing = 1.sp
                            )
                        }

                        OutlinedButton(
                            onClick = { showNewEngDialog = true },
                            modifier = Modifier.testTag("btn_new_engagement")
                        ) {
                            Icon(Icons.Default.Add, contentDescription = "New", modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("New Engagement", fontSize = 12.sp)
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Text(
                        text = currentEng?.title ?: "Perimeter Posture Assessment",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Assessor: ${currentEng?.leadAssessor ?: "Lead SecOps Assessor"} • Status: ${currentEng?.status?.label ?: "Active"}",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "Target Mode: Non-Destructive Defensive Scanning Only",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        color = SeverityClean
                    )
                }
            }
        }

        // 2. Written Rules of Engagement (ROA) Authorization
        item {
            val isPermitted = currentAuth?.explicitTestingPermitted == true
            val authStatus = currentAuth?.verificationStatus ?: com.example.data.model.AuthorizationStatus.PENDING_VERIFICATION
            val statusColor = when (authStatus) {
                com.example.data.model.AuthorizationStatus.VERIFIED -> SeverityClean
                com.example.data.model.AuthorizationStatus.PENDING_VERIFICATION -> SeverityMedium
                else -> SeverityCritical
            }

            Card(
                colors = CardDefaults.cardColors(containerColor = CyberSlate900),
                border = androidx.compose.foundation.BorderStroke(1.dp, statusColor.copy(alpha = 0.8f)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().testTag("roa_authorization_card")
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Description,
                                contentDescription = "Written Authorization",
                                tint = statusColor,
                                modifier = Modifier.size(22.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "WRITTEN AUTHORIZATION (ROA)",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = statusColor,
                                letterSpacing = 1.sp
                            )
                        }

                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(statusColor.copy(alpha = 0.2f))
                                .padding(horizontal = 8.dp, vertical = 3.dp)
                        ) {
                            Text(
                                text = authStatus.label,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = statusColor
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    if (currentAuth != null) {
                        Text(
                            text = "Reference Document: ${currentAuth?.documentReference}",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Authorized By: ${currentAuth?.authorizedByName} (${currentAuth?.authorizedByRole})",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "Emergency Contact: ${currentAuth?.emergencyContactPhone}",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        if (!currentAuth?.evidenceHash.isNullOrBlank()) {
                            Text(
                                text = "Document Hash: ${currentAuth?.evidenceHash}",
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        if (!currentAuth?.verifiedBy.isNullOrBlank()) {
                            Text(
                                text = "Verified By Auditor: ${currentAuth?.verifiedBy}",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = SeverityClean
                            )
                        }

                        if (currentAuth?.verificationStatus == com.example.data.model.AuthorizationStatus.REVOKED) {
                            Text(
                                text = "REVOKED: ${currentAuth?.revocationReason ?: "Assessor Demand"}",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = SeverityCritical
                            )
                        }

                        val validTo = dateFormat.format(Date(currentAuth?.validToTimestamp ?: System.currentTimeMillis()))
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = if (isPermitted) "Window: Valid until $validTo (Testing Permitted)" else "Window: Valid until $validTo (Active Testing Blocked)",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = if (isPermitted) SeverityClean else SeverityCritical
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedButton(
                                onClick = { showAuthDialog = true },
                                modifier = Modifier.weight(1f).testTag("btn_edit_roa")
                            ) {
                                Text("Edit ROA", fontSize = 11.sp)
                            }

                            if (!isPermitted) {
                                Button(
                                    onClick = { showVerifyDialog = true },
                                    colors = ButtonDefaults.buttonColors(containerColor = SeverityClean),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.weight(1f).testTag("btn_verify_roa")
                                ) {
                                    Text("Verify ROA", color = CyberSlate900, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                                }
                            } else {
                                OutlinedButton(
                                    onClick = { showRevokeDialog = true },
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = SeverityCritical),
                                    modifier = Modifier.weight(1f).testTag("btn_revoke_roa")
                                ) {
                                    Text("Revoke ROA", fontSize = 11.sp)
                                }
                            }
                        }
                    } else {
                        Text(
                            text = "NO SIGNED AUTHORIZATION ON RECORD",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = SeverityCritical
                        )
                        Text(
                            text = "Active testing is strictly blocked until a signed Rules of Engagement (ROA) is confirmed.",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = { showAuthDialog = true },
                            colors = ButtonDefaults.buttonColors(containerColor = SentinelCyan),
                            modifier = Modifier.testTag("btn_add_roa")
                        ) {
                            Text("Submit Rules of Engagement", color = CyberSlate900, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                }
            }
        }

        // 3. Approved Scopes Header & Action
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "APPROVED TARGET SCOPES (${scopes.size})",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = SentinelCyan,
                        letterSpacing = 1.sp
                    )
                    Text(
                        text = "Backend strictly drops requests outside these approved boundaries.",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Button(
                    onClick = { showAddScopeDialog = true },
                    colors = ButtonDefaults.buttonColors(containerColor = SentinelCyan),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.testTag("btn_add_scope")
                ) {
                    Icon(Icons.Default.Add, contentDescription = "Add Scope", tint = CyberSlate900, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Add Target", color = CyberSlate900, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
            }
        }

        // 4. Scope Items List
        if (scopes.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "No scopes approved yet. Add an authorized domain to start testing.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 13.sp
                    )
                }
            }
        } else {
            items(scopes) { scope ->
                ScopeCard(scope = scope, onDelete = { viewModel.removeScope(scope) })
            }
        }
    }

    // Dialog: Add Approved Target Scope
    if (showAddScopeDialog) {
        var hostInput by remember { mutableStateOf("") }
        var wildcardAllowed by remember { mutableStateOf(false) }
        var portsInput by remember { mutableStateOf("80,443") }

        AlertDialog(
            onDismissRequest = { showAddScopeDialog = false },
            title = { Text("Add Approved Target Hostname", fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = "Ensure the client has given explicit written authorization for this hostname.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    OutlinedTextField(
                        value = hostInput,
                        onValueChange = { hostInput = it },
                        label = { Text("Hostname (e.g. scanme.nmap.org)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_scope_host")
                    )

                    OutlinedTextField(
                        value = portsInput,
                        onValueChange = { portsInput = it },
                        label = { Text("Allowed Ports") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_scope_ports")
                    )

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = wildcardAllowed,
                            onCheckedChange = { wildcardAllowed = it },
                            colors = CheckboxDefaults.colors(checkedColor = SentinelCyan)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Allow Subdomains (Wildcard *.host)", fontSize = 13.sp)
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (hostInput.isNotBlank()) {
                            viewModel.addApprovedScope(hostInput, wildcardAllowed, portsInput)
                            showAddScopeDialog = false
                        }
                    },
                    modifier = Modifier.testTag("btn_confirm_add_scope")
                ) {
                    Text("Add to Approved Scope")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAddScopeDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Dialog: Confirm or Update Authorization Record (ROA)
    if (showAuthDialog) {
        var authName by remember { mutableStateOf(currentAuth?.authorizedByName ?: "David Vance, CISO") }
        var authRole by remember { mutableStateOf(currentAuth?.authorizedByRole ?: "Chief Information Security Officer") }
        var authEmail by remember { mutableStateOf(currentAuth?.authorizedByEmail ?: "ciso@acme-corp.internal") }
        var docRef by remember { mutableStateOf(currentAuth?.documentReference ?: "ROA-SIGNED-SOW-2026-0492.PDF") }
        var phone by remember { mutableStateOf(currentAuth?.emergencyContactPhone ?: "+1-555-019-8234") }
        var evidenceHash by remember { mutableStateOf(currentAuth?.evidenceHash ?: "") }

        AlertDialog(
            onDismissRequest = { showAuthDialog = false },
            title = { Text("Submit Written Authorization (ROA)", fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "Submitting documentation enters PENDING_VERIFICATION state. Testing remains blocked until explicit auditor verification.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    OutlinedTextField(
                        value = authName,
                        onValueChange = { authName = it },
                        label = { Text("Authorizing Officer Name") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_auth_name")
                    )

                    OutlinedTextField(
                        value = authRole,
                        onValueChange = { authRole = it },
                        label = { Text("Role / Title") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_auth_role")
                    )

                    OutlinedTextField(
                        value = authEmail,
                        onValueChange = { authEmail = it },
                        label = { Text("Corporate Email") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_auth_email")
                    )

                    OutlinedTextField(
                        value = docRef,
                        onValueChange = { docRef = it },
                        label = { Text("Document Reference (SOW/ROA PDF)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_auth_docref")
                    )

                    OutlinedTextField(
                        value = evidenceHash,
                        onValueChange = { evidenceHash = it },
                        label = { Text("Document Evidence SHA-256 Hash") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_auth_hash")
                    )

                    OutlinedTextField(
                        value = phone,
                        onValueChange = { phone = it },
                        label = { Text("24/7 Emergency Phone") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_auth_phone")
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.submitAuthorization(authName, authRole, authEmail, docRef, phone, evidenceHash)
                        showAuthDialog = false
                    },
                    modifier = Modifier.testTag("btn_confirm_auth")
                ) {
                    Text("Save Documentation")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAuthDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Dialog: Auditor Verification of Written Authorization
    if (showVerifyDialog && currentAuth != null) {
        var auditorName by remember { mutableStateOf("Lead Auditor (CISSP)") }
        var verifiedHash by remember { mutableStateOf(currentAuth?.evidenceHash?.ifBlank { "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069" } ?: "") }

        AlertDialog(
            onDismissRequest = { showVerifyDialog = false },
            title = { Text("Auditor Verification of ROA", fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "I attest that I have verified the client's signed written Rules of Engagement document and verified its cryptographic hash before permitting active defensive checks.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    OutlinedTextField(
                        value = auditorName,
                        onValueChange = { auditorName = it },
                        label = { Text("Verifying Auditor Name & Credential") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_verify_auditor")
                    )

                    OutlinedTextField(
                        value = verifiedHash,
                        onValueChange = { verifiedHash = it },
                        label = { Text("Verified Document SHA-256 Hash") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_verify_hash")
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (auditorName.isNotBlank()) {
                            viewModel.verifyAuthorization(currentAuth!!, auditorName, verifiedHash)
                            showVerifyDialog = false
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = SeverityClean),
                    modifier = Modifier.testTag("btn_confirm_verify_roa")
                ) {
                    Text("Grant Testing Permission", color = CyberSlate900, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showVerifyDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Dialog: Revoke Authorization
    if (showRevokeDialog && currentAuth != null) {
        var revokeReason by remember { mutableStateOf("Client requested immediate cessation of assessment activities.") }

        AlertDialog(
            onDismissRequest = { showRevokeDialog = false },
            title = { Text("Revoke Authorization", fontWeight = FontWeight.Bold, color = SeverityCritical) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "Revoking authorization immediately invalidates active testing permission. All in-flight and future scans against this engagement will be blocked.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    OutlinedTextField(
                        value = revokeReason,
                        onValueChange = { revokeReason = it },
                        label = { Text("Revocation Reason") },
                        singleLine = false,
                        maxLines = 3,
                        modifier = Modifier.fillMaxWidth().testTag("input_revoke_reason")
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.revokeAuthorization(currentAuth!!, revokeReason)
                        showRevokeDialog = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = SeverityCritical),
                    modifier = Modifier.testTag("btn_confirm_revoke_roa")
                ) {
                    Text("Confirm Revocation", fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showRevokeDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Dialog: Create New Engagement
    if (showNewEngDialog) {
        var orgInput by remember { mutableStateOf("") }
        var nameInput by remember { mutableStateOf("") }
        var emailInput by remember { mutableStateOf("") }
        var titleInput by remember { mutableStateOf("Q4 Security Posture Review") }
        var initialTarget by remember { mutableStateOf("example.com") }

        AlertDialog(
            onDismissRequest = { showNewEngDialog = false },
            title = { Text("New Client Engagement", fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = orgInput,
                        onValueChange = { orgInput = it },
                        label = { Text("Client Organization") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_new_org")
                    )

                    OutlinedTextField(
                        value = nameInput,
                        onValueChange = { nameInput = it },
                        label = { Text("Contact Person") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_new_contact")
                    )

                    OutlinedTextField(
                        value = emailInput,
                        onValueChange = { emailInput = it },
                        label = { Text("Email Address") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_new_email")
                    )

                    OutlinedTextField(
                        value = titleInput,
                        onValueChange = { titleInput = it },
                        label = { Text("Engagement Title") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_new_title")
                    )

                    OutlinedTextField(
                        value = initialTarget,
                        onValueChange = { initialTarget = it },
                        label = { Text("Initial Approved Target (Hostname)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("input_new_target")
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (orgInput.isNotBlank() && initialTarget.isNotBlank()) {
                            viewModel.createEngagement(orgInput, nameInput, emailInput, titleInput, initialTarget)
                            showNewEngDialog = false
                        }
                    },
                    modifier = Modifier.testTag("btn_confirm_create_eng")
                ) {
                    Text("Create Engagement")
                }
            },
            dismissButton = {
                TextButton(onClick = { showNewEngDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
fun ScopeCard(
    scope: ApprovedScopeEntity,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = CyberSlate900),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberSlate700),
        shape = RoundedCornerShape(10.dp),
        modifier = modifier.fillMaxWidth().testTag("scope_item_${scope.hostname}")
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(SentinelCyan.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Language,
                        contentDescription = "Host",
                        tint = SentinelCyan,
                        modifier = Modifier.size(20.dp)
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = scope.hostname,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        if (scope.wildcardAllowed) {
                            Spacer(modifier = Modifier.width(6.dp))
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(SentinelCyan.copy(alpha = 0.2f))
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = "*.SUBDOMAINS",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = SentinelCyan
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "Ports: ${scope.allowedPorts} • Path: ${scope.pathPrefix} • Status: Active",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            IconButton(
                onClick = onDelete,
                modifier = Modifier.testTag("btn_delete_scope_${scope.hostname}")
            ) {
                Icon(
                    imageVector = Icons.Default.Delete,
                    contentDescription = "Remove Scope",
                    tint = SeverityCritical.copy(alpha = 0.8f)
                )
            }
        }
    }
}
