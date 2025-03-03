import matplotlib.pyplot as plt
import numpy as np

# 数据
schemes = ['512']
cdPRE = {
    'KG': [8948],
    'Enc': [9572],
    'Dec': [802],
    'RKG': [11858],
    'REnc': [406]
}
CPA_PRE = {
    'KG': [17898],
    'Enc': [9514],
    'Dec': [798],
    'RKG': [128470],
    'REnc': [4486]
}

# 创建子图
fig, axs = plt.subplots(3, 2, figsize=(5, 8))

# 定义颜色
color_cdPRE = '#1f77b4'
color_CPA_PRE = '#ff7f0e'

# 绘制每个参数的对比图
for i, (param, cdPRE_values) in enumerate(cdPRE.items()):
    CPA_PRE_values = CPA_PRE[param]
    ax = axs[i // 2, i % 2]
    x = np.arange(len(schemes))
    width = 4  # 调整柱状图的宽度

    ax.bar(x - width/2, CPA_PRE_values, 1, label='CPA PRE', color=color_CPA_PRE)
    ax.bar(x + width/2, cdPRE_values, 1, label='cdPRE', color=color_cdPRE)

    # 添加数值标签
    for container in ax.containers:
        ax.bar_label(container, fontsize=8, rotation=0, padding=3)

    ax.set_ylabel('Alder Lake Cycles')
    ax.set_title(f'{param} Comparison')
    ax.set_xticks([])
    ax.legend()

    ax.set_ylim(0, max(max(cdPRE_values), max(CPA_PRE_values)) * 1.6)

# 绘制整体数据的对比图
overall_cdPRE = [sum(values) for values in zip(*cdPRE.values())]
overall_CPA_PRE = [sum(values) for values in zip(*CPA_PRE.values())]
ax = axs[2, 1]
x = np.arange(len(schemes))
width = 4

ax.bar(x - width/2, overall_CPA_PRE, 1, label='CPA PRE', color=color_CPA_PRE)
ax.bar(x + width/2, overall_cdPRE, 1, label='cdPRE', color=color_cdPRE)

# 添加数值标签
for container in ax.containers:
    ax.bar_label(container, fontsize=8, rotation=0, padding=5)

ax.set_ylabel('Alder Lake Cycles')
ax.set_title('Overall Comparison')
ax.set_xticks([])
ax.legend()

ax.set_ylim(0, max(max(overall_cdPRE), max(overall_CPA_PRE)) * 1.6)

# 调整子图间距
plt.subplots_adjust(wspace=0.3, hspace=0.5)

# 调整布局
plt.tight_layout(rect=[0, 0.03, 1, 0.95])
plt.show()