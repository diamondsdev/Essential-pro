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

    val dateFormat = remember { SimpleDateFormat("MMM dd, yyyy", Locale.US) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag("engagement_screen_list"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
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
            Card(
                colors = CardDefaults.cardColors(containerColor = CyberSlate900),
                border = androidx.compose.foundation.BorderStroke(
                    1.dp,
                    if (currentAuth?.explicitTestingPermitted == true) SeverityClean.copy(alpha = 0.5f) else SeverityCritical
                ),
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
                                tint = if (currentAuth != null) SeverityClean else SeverityCritical,
                                modifier = Modifier.size(22.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "WRITTEN AUTHORIZATION (ROA)",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (currentAuth != null) SeverityClean else SeverityCritical,
                                letterSpacing = 1.sp
                            )
                        }

                        IconButton(
                            onClick = { showAuthDialog = true },
                            modifier = Modifier.testTag("btn_edit_roa")
                        ) {
                            Icon(Icons.Default.Edit, contentDescription = "Edit ROA", tint = SentinelCyan)
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

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

                        val validTo = dateFormat.format(Date(currentAuth?.validToTimestamp ?: System.currentTimeMillis()))
                        Text(
                            text = "Window: Valid until $validTo (Explicit Consent Granted)",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = SeverityClean
                        )
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

        AlertDialog(
            onDismissRequest = { showAuthDialog = false },
            title = { Text("Confirm Written Authorization (ROA)", fontWeight = FontWeight.Bold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "A signed agreement is legally mandatory before conducting defensive checks.",
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
                        viewModel.confirmAuthorization(authName, authRole, authEmail, docRef, phone)
                        showAuthDialog = false
                    },
                    modifier = Modifier.testTag("btn_confirm_auth")
                ) {
                    Text("Save & Enforce Authorization")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAuthDialog = false }) {
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
