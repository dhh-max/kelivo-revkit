package com.shinegirls.apkadremovereditor

import android.os.Bundle
import android.util.Log
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.shinegirls.apkadremovereditor.core.AdPatternConfig
import com.shinegirls.apkadremovereditor.core.AdPatternConfig.Category
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText

/**
 * 广告特征配置设置界面。
 *
 * 功能：
 * - 读取并显示当前配置文件中的广告特征
 * - 按分类显示各特征条目数量
 * - 点击"管理"进入特征列表，可查看、编辑、删除、添加单条特征
 * - 保存配置到 JSON 文件
 * - 重置为默认配置
 */
class SettingsActivity : AppCompatActivity() {

    private lateinit var tvConfigPath: TextView
    private lateinit var tvConfigStats: TextView
    private lateinit var btnSave: MaterialButton
    private lateinit var btnReset: MaterialButton

    private var config: AdPatternConfig.AdPatterns = AdPatternConfig.AdPatterns()

    // 分类卡片视图引用
    private val categoryCards = mutableMapOf<Category, View>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            setContentView(R.layout.activity_settings)
        } catch (e: Exception) {
            Log.e("SettingsActivity", "布局加载失败", e)
            Toast.makeText(this, "设置界面加载失败: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
            return
        }

        try {
            val toolbar = findViewById<Toolbar>(R.id.toolbar)
            setSupportActionBar(toolbar)
            supportActionBar?.setDisplayHomeAsUpEnabled(true)
            toolbar.setNavigationOnClickListener { finish() }

            tvConfigPath = findViewById(R.id.tvConfigPath)
            tvConfigStats = findViewById(R.id.tvConfigStats)
            btnSave = findViewById(R.id.btnSave)
            btnReset = findViewById(R.id.btnReset)

            // 加载配置
            loadAndDisplayConfig()

            // 保存按钮
            btnSave.setOnClickListener {
                val success = AdPatternConfig.saveConfig(config)
                if (success) {
                    Toast.makeText(this, "配置已保存", Toast.LENGTH_SHORT).show()
                    updateStats()
                } else {
                    Toast.makeText(this, "保存失败，请检查存储权限", Toast.LENGTH_LONG).show()
                }
            }

            // 重置默认按钮
            btnReset.setOnClickListener {
                AlertDialog.Builder(this)
                    .setTitle("重置默认配置")
                    .setMessage("确定要恢复所有广告特征为内置默认值？\n当前自定义修改将丢失。")
                    .setPositiveButton("重置") { _, _ ->
                        config = AdPatternConfig.resetToDefault(this)
                        displayConfig()
                        Toast.makeText(this, "已重置为默认配置", Toast.LENGTH_SHORT).show()
                    }
                    .setNegativeButton("取消", null)
                    .show()
            }
        } catch (e: Exception) {
            Log.e("SettingsActivity", "初始化失败", e)
            Toast.makeText(this, "设置初始化失败: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
        }
    }

    /**
     * 加载配置并显示。
     */
    private fun loadAndDisplayConfig() {
        try {
            config = AdPatternConfig.loadConfig(this)
        } catch (e: Exception) {
            Log.e("SettingsActivity", "加载配置失败，使用默认配置", e)
            config = AdPatternConfig.AdPatterns()
        }
        displayConfig()
    }

    /**
     * 显示配置内容到 UI。
     */
    private fun displayConfig() {
        tvConfigPath.text = AdPatternConfig.getConfigFile().absolutePath
        updateStats()

        // 绑定各分类卡片
        bindCategoryCard(R.id.cardSdkPackages, Category.SDK_PACKAGES)
        bindCategoryCard(R.id.cardClassKeywords, Category.CLASS_KEYWORDS)
        bindCategoryCard(R.id.cardMethodPatterns, Category.METHOD_PATTERNS)
        bindCategoryCard(R.id.cardUrlPatterns, Category.URL_PATTERNS)
        bindCategoryCard(R.id.cardAdViewNames, Category.AD_VIEW_NAMES)
        bindCategoryCard(R.id.cardAdActivities, Category.AD_ACTIVITIES)
        bindCategoryCard(R.id.cardAdServices, Category.AD_SERVICES)
        bindCategoryCard(R.id.cardAdReceivers, Category.AD_RECEIVERS)
        bindCategoryCard(R.id.cardForceTrueMethods, Category.FORCE_TRUE_METHODS)
    }

    /**
     * 更新统计信息。
     */
    private fun updateStats() {
        tvConfigStats.text = "共 ${config.totalCount()} 条特征"
    }

    /**
     * 绑定分类卡片视图，设置名称、数量和管理按钮。
     */
    private fun bindCategoryCard(cardId: Int, category: Category) {
        try {
            val card = findViewById<View>(cardId) ?: run {
                Log.w("SettingsActivity", "卡片视图未找到: cardId=$cardId")
                return
            }
            categoryCards[category] = card

            val tvName = card.findViewById<TextView>(R.id.tvCategoryName)
            val tvCount = card.findViewById<TextView>(R.id.tvCategoryCount)
            val btnManage = card.findViewById<MaterialButton>(R.id.btnManage)

            if (tvName == null || tvCount == null || btnManage == null) {
                Log.w("SettingsActivity", "卡片子视图未找到: $category")
                return
            }

            tvName.text = category.displayName
            val list = AdPatternConfig.getCategoryList(config, category)
            tvCount.text = "${list.size} 条"

            btnManage.setOnClickListener {
                showPatternListDialog(category)
            }
        } catch (e: Exception) {
            Log.e("SettingsActivity", "绑定分类卡片失败: $category", e)
        }
    }

    /**
     * 显示指定分类的特征列表对话框。
     * 支持：查看列表、添加、编辑、删除单条特征。
     */
    private fun showPatternListDialog(category: Category) {
        val list = AdPatternConfig.getCategoryList(config, category)

        val dialogView = layoutInflater.inflate(R.layout.dialog_pattern_list, null)
        val rvPatterns = dialogView.findViewById<RecyclerView>(R.id.rvPatterns)
        val etNewPattern = dialogView.findViewById<TextInputEditText>(R.id.etNewPattern)
        val btnAddPattern = dialogView.findViewById<MaterialButton>(R.id.btnAddPattern)
        val tvEmptyHint = dialogView.findViewById<TextView>(R.id.tvEmptyHint)

        val adapter = PatternAdapter(list, object : PatternAdapter.Callback {
            override fun onEdit(position: Int, oldValue: String) {
                showEditDialog(category, oldValue) { newValue ->
                    if (newValue.isNotBlank() && newValue != oldValue) {
                        // 检查是否已存在
                        if (list.any { it.equals(newValue, ignoreCase = true) }) {
                            Toast.makeText(this@SettingsActivity, "该特征已存在", Toast.LENGTH_SHORT).show()
                            return@showEditDialog
                        }
                        list[position] = newValue.trim()
                        rvPatterns.adapter?.notifyItemChanged(position)
                        updateEmptyHint(list, tvEmptyHint)
                        // 实时保存
                        AdPatternConfig.saveConfig(config)
                        updateCategoryCount(category, list.size)
                    }
                }
            }

            override fun onDelete(position: Int) {
                AlertDialog.Builder(this@SettingsActivity)
                    .setTitle("删除特征")
                    .setMessage("确定删除 \"${list[position].take(50)}\" ？")
                    .setPositiveButton("删除") { _, _ ->
                        list.removeAt(position)
                        rvPatterns.adapter?.notifyItemRemoved(position)
                        rvPatterns.adapter?.notifyItemRangeChanged(position, list.size)
                        updateEmptyHint(list, tvEmptyHint)
                        // 实时保存
                        AdPatternConfig.saveConfig(config)
                        updateCategoryCount(category, list.size)
                        updateStats()
                    }
                    .setNegativeButton("取消", null)
                    .show()
            }
        })

        rvPatterns.layoutManager = LinearLayoutManager(this)
        rvPatterns.adapter = adapter

        // 添加按钮
        btnAddPattern.setOnClickListener {
            val text = etNewPattern.text.toString().trim()
            if (text.isEmpty()) {
                Toast.makeText(this, "请输入特征内容", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            if (list.any { it.equals(text, ignoreCase = true) }) {
                Toast.makeText(this, "该特征已存在", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            list.add(text)
            rvPatterns.adapter?.notifyItemInserted(list.size - 1)
            rvPatterns.scrollToPosition(list.size - 1)
            etNewPattern.text?.clear()
            updateEmptyHint(list, tvEmptyHint)
            // 实时保存
            AdPatternConfig.saveConfig(config)
            updateCategoryCount(category, list.size)
            updateStats()
            Toast.makeText(this, "已添加", Toast.LENGTH_SHORT).show()
        }

        updateEmptyHint(list, tvEmptyHint)

        AlertDialog.Builder(this)
            .setTitle(category.displayName + " (${list.size} 条)")
            .setView(dialogView)
            .setPositiveButton("关闭", null)
            .setOnDismissListener {
                updateCategoryCount(category, list.size)
                updateStats()
            }
            .show()
    }

    /**
     * 显示编辑对话框。
     */
    private fun showEditDialog(category: Category, oldValue: String, onSave: (String) -> Unit) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT
            setText(oldValue)
            setSelection(oldValue.length)
            setSingleLine(true)
        }

        AlertDialog.Builder(this)
            .setTitle("编辑特征")
            .setView(input)
            .setPositiveButton("保存") { _, _ ->
                onSave(input.text.toString().trim())
            }
            .setNegativeButton("取消", null)
            .show()
    }

    /**
     * 更新空列表提示。
     */
    private fun updateEmptyHint(list: List<*>, tvEmptyHint: TextView) {
        tvEmptyHint.visibility = if (list.isEmpty()) View.VISIBLE else View.GONE
    }

    /**
     * 更新分类卡片上的数量显示。
     */
    private fun updateCategoryCount(category: Category, count: Int) {
        val card = categoryCards[category] ?: return
        val tvCount = card.findViewById<TextView>(R.id.tvCategoryCount)
        tvCount.text = "$count 条"
    }
}

/**
 * 特征列表 RecyclerView 适配器。
 */
class PatternAdapter(
    private val items: MutableList<String>,
    private val callback: Callback
) : RecyclerView.Adapter<PatternAdapter.ViewHolder>() {

    interface Callback {
        fun onEdit(position: Int, oldValue: String)
        fun onDelete(position: Int)
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvPatternText: TextView = view.findViewById(R.id.tvPatternText)
        val btnEdit: ImageButton = view.findViewById(R.id.btnEditItem)
        val btnDelete: ImageButton = view.findViewById(R.id.btnDeleteItem)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_pattern, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.tvPatternText.text = item

        holder.btnEdit.setOnClickListener {
            val pos = holder.adapterPosition
            if (pos != RecyclerView.NO_POSITION) {
                callback.onEdit(pos, items[pos])
            }
        }

        holder.btnDelete.setOnClickListener {
            val pos = holder.adapterPosition
            if (pos != RecyclerView.NO_POSITION) {
                callback.onDelete(pos)
            }
        }
    }

    override fun getItemCount(): Int = items.size
}
